/* $Id: rex.C,v 1.120 2004/09/19 22:02:25 dm Exp $ */

/*
 *
 * Copyright (C) 2000-2001 Eric Peterson (ericp@lcs.mit.edu)
 * Copyright (C) 2000-2001 Michael Kaminsky (kaminsky@lcs.mit.edu)
 * Copyright (C) 2000 David Mazieres (dm@uun.org)
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

#include "rex.h"
#include "rexcommon.h"
#include "sfskeymisc.h"
#include "sfstty.h"

#ifndef PATH_XAUTH
# define PATH_XAUTH "xauth"
#endif /* PATH_XAUTH */

struct module_pair {
  str local;
  str remote;
};

/* todo: this should be moved into global include, since it's defined
	 elsewhere */
#define XPREFIX "/tmp/.X11-unix/X"

static ptr<agentconn> aconn;
static str dest;
static str schost;
static ptr<sfscon> sfsc = NULL;
static rexsession *sess = NULL;
static sfs_seqno seqno, orig_seqno;
static ptr<axprt_crypt> proxyxprt = NULL;

vec<module_pair> modules;
static bool opt_notty = false;
static bool opt_tty = false;
static bool opt_noX = false;
static bool opt_verbose = false;
static bool opt_quiet = false;
static bool opt_forwardagent = true;
static bool opt_resumable = false;
static int exitstatus = 0;

static vec<str> command;
void madesession ();

static void
simulateeof ()
{
  if (proxyxprt)
    close (proxyxprt->reclaim ());
}

static void
endcbcalled () {
//   warn ("endcb called\n");
  exit (exitstatus);
}

////////////////////////////channels used to exec command w/o tty support

class execfd : public unixfd
{
private:
  int *numleft;

public:
  execfd (rexchannel *pch, int fd, int localfd, int *numleft) :
    unixfd (pch, fd, localfd, -1, localfd == 2, true), numleft (numleft)
  {}

  virtual ~execfd ()
  {
    //todo : this should be changed so that it is ssh like, prompting
    //	     that there are remaining connections, etc.
    //	   warn ("--reached ~execfd with %d execfds left\n", *numleft);
    if (!--*numleft)
      sess->quit ();
  }
};

class execchannel : public rexchannel
{
private:
  int fdsleft;
  
  static vec<str>
  fixpath (vec<str> command)
  {
    if (command.size () == 1 && command[0] == ".")
      return command;

    vec<str> execcommand;
    strbuf sb;
    str sep (" ");
    
    execcommand.push_back (".");
    execcommand.push_back ("-c");

    sb.cat (command[0]);
    for (int ix = 1; implicit_cast <u_int32_t> (ix) < command.size (); ix++)
      sb.cat (sep).cat (command[ix]);
    execcommand.push_back (sb);

    return execcommand;
  }

public:
  execchannel (rexsession *sess, vec<str> command) :
    rexchannel::rexchannel (sess, 3, fixpath (command)), fdsleft(3) {}

  void
  madechannel (int error)
  {
    if (error) {
      warn << "command not found\n";
      exit (error);
    }
    vNew refcounted<execfd> (this, 0, 0, &fdsleft);
    vNew refcounted<execfd> (this, 1, 1, &fdsleft);
    vNew refcounted<execfd> (this, 2, 2, &fdsleft);
    sess->setendcb (wrap (endcbcalled));
  }

  void
  exited (int status) {
    exitstatus = status;
    rexchannel::exited (status);
  }
};

//////////////////////////////////tty channel classes

class ttyfd : public unixfd
{
private:
  bool saw_newline;
  bool saw_escape;
  char escape_switch_char;

  void rcb () {
    if (reof)
      return;
    char buf[8192];
    ssize_t n = read (localfd_in, buf, sizeof (buf));
    if (n < 0) {
      if (errno != EAGAIN)
	abort ();
      return;
    }

    vec<char, 1024> new_data;

    for (int i = 0; i < n; i++) {
      if (saw_escape) {
	saw_escape = false;
	escape_switch_char = buf[i];
	switch (escape_switch_char) {
	case '?':
	  warnx << "Escape sequences:\n\r"
		<< "~.  - terminate connection\n\r"
		<< "~^Z - suspend connection\n\r"
		<< "~?  - help\n\r"
		<< "~~  - send the escape character\n\r"
		<< "(Escape sequences are recognized only after a newline.)\r\n";
	  continue;
	case '.':
	  leave_raw_mode ();
	  warn << "\nTerminating rex connection\n";
	  readeof ();
	  exit (1);
	case 'Z' - 64:
	  leave_raw_mode ();
	  warn << "\nSuspending rex connection\n";
	  kill(getpid(), SIGTSTP);
	  enter_raw_mode ();
	  continue;
	case '~':
	  break;
	default:
	  new_data.push_back ('~');
	  break;
	}
      }
      if (saw_newline && buf[i] == '~')
	saw_escape = true;
      else {
	saw_escape = false;
	new_data.push_back (buf[i]);
      }
      if (buf[i] == '\r' || buf[i] == '\n')
	saw_newline = true;
      else
	saw_newline = false;
    }

    if (!new_data.empty ()) {
      rex_payload arg;
      arg.channel = channo;
      arg.fd = fd;
      arg.data.set (new_data.base (), new_data.size ());
      ref<bool> pres (New refcounted<bool> (false));
      proxy->call (REX_DATA, &arg, pres,
		   wrap (implicit_cast<ref<unixfd> > (mkref (this)),
			 &unixfd::datacb, n, pres));
      rsize += n;
      if (rsize >= hiwat)
	fdcb (localfd_in, selread, NULL);
    }
  }

public:
  ttyfd (rexchannel *pch, int fd, int localfd_in, int localfd_out)
    //	  : unixfd::unixfd (pch, fd, localfd_in, localfd_out, true, true),
	: unixfd::unixfd (pch, fd, localfd_in, localfd_out, true, false),
      saw_newline (false), saw_escape (false)
  {
    // warn << "CONSTRUCT ttyfd\n";
  }
    
  ~ttyfd ()
  {
    //todo : should check for port forwarding channels and
    //	     prompt user (like ssh)

    leave_raw_mode ();

    // warn << "~ttyfd\n";
  }
};

class ttychannelfd : public rexfd
{
private:
  bool garbage_bool;
  int fd_in, fd_out, masterfd;

public:
  void
  newfd (svccb *sbp)
  {
    rexcb_newfd_arg *arg = sbp->Xtmpl getarg<rexcb_newfd_arg> ();

    masterfd = arg->newfd;
    vNew refcounted<ttyfd> (pch, masterfd, fd_in, fd_out);
    
    enter_raw_mode ();
    sbp->replyref (true);

    sendnewwindowsize();   
  }

  void
  sendnewwindowsize ()
  {
    struct winsize windowsize;
    str sws = windowsizetostring (&windowsize);

    rex_payload arg;
    arg.channel = channo;
    arg.fd = fd;
  
    arg.data.set (const_cast<char *> (sws.cstr ()), sws.len ());

    proxy->call (REX_DATA, &arg, &garbage_bool, aclnt_cb_null);

    sigcb (SIGWINCH, wrap (this, &ttychannelfd::sendnewwindowsize));
  }

  ttychannelfd (rexchannel *pch, int fd_in, int fd_out)
    : rexfd (pch, fd_in), fd_in (fd_in), fd_out (fd_out), masterfd (-1) { 
//     warn << "CONSTRUCT ttychannelfd\n";
  }

  ~ttychannelfd () {
    sigcb (SIGWINCH, NULL);
    sess->quit ();

    if (masterfd >= 0)
      pch->remove_fd (masterfd);
    else
      warn << "command not found\n";

//     warn << "~ttychannelfd\n";
  }
};

class ttychannel : public rexchannel
{
private:
  static vec<str>
  fixpath (vec<str> command)
  {
    vec<str> ttycommand;
    
    ttycommand.push_back ("ttyd");
    ttycommand.push_back (myname ());
    ttycommand.push_back (".");

    if (!(command.size () == 1 && command[0] == ".")) {
      strbuf sb;
      str sep (" ");

      sb.cat (command[0]);
      for (int ix = 1; implicit_cast <u_int32_t> (ix) < command.size (); ix++)
	sb.cat (sep).cat (command[ix]);

      ttycommand.push_back ("-c");
      ttycommand.push_back (sb);
    }

    return ttycommand;
  }
  
public:
  void
  exited (int status) {
    exitstatus = status;
    rexchannel::exited (status);
  }

  void
  madechannel (int error)
  {
    if (error) {
      warn << "could not find/run ttyd on server\n";
      exit (error);
    }
    vNew refcounted<ttychannelfd> (this, 0, 1);
    sess->setendcb (wrap (endcbcalled));
  }

  ttychannel (rexsession *sess, vec<str> command) :
    rexchannel::rexchannel (sess, 1, fixpath (command)) {}

  virtual
  ~ttychannel () {}
};

////////////X forwarding utility functions

class xclientfd : public unixfd {
  size_t x11_data_len;
  char *x11_real_data;
  char *x11_fake_data;
  char *x11_proto;

  bool cookie_replaced;
  str conn_head;

public:
  xclientfd (rexchannel *pch, int fd, int localfd,
	     char *x11_real_data, char *x11_fake_data, size_t x11_data_len,
	     char *x11_proto) :
    unixfd (pch, fd, localfd), x11_data_len (x11_data_len),
    x11_real_data(x11_real_data), x11_fake_data(x11_fake_data),
    x11_proto(x11_proto), cookie_replaced (false), conn_head ("")
  {}

  void
  data (svccb *sbp) {
    //XXX: replace this with unixfd, so we don't have to dispatch to unixfd
    //	   on every data write, inefficient
    if (cookie_replaced) {
      unixfd::data (sbp);
      return;
    }
    
    rex_payload *argp = sbp->Xtmpl getarg<rex_payload> ();
    size_t len = argp->data.size (); 
    
    if (len) {
      u_int proto_len, data_len;
      conn_head = strbuf () << conn_head << str (argp->data.base (), len);
      size_t chlen = conn_head.len ();
      if (chlen >= 12) {
	if (conn_head[0] == 0x42) {	/* Byte order MSB first. */
	  proto_len = 256 * conn_head[6] + conn_head[7];
	  data_len = 256 * conn_head[8] + conn_head[9];
	} else if (conn_head[0] == 0x6c) {	/* Byte order LSB first. */
	  proto_len = conn_head[6] + 256 * conn_head[7];
	  data_len = conn_head[8] + 256 * conn_head[9];
	} else {
	  warn ("Initial X11 packet contains bad byte order byte: 0x%x",
		conn_head[0]);
	  sbp->replyref (false);
          abort ();
	  return;
	}

	/* Check if the whole packet is in buffer. */
	if (chlen < 12 + ((proto_len + 3) & ~3) +
	    ((data_len + 3) & ~3)) {
	  sbp->replyref (true);
	  return;
	}

	/* Check if authentication protocol matches. */
	if (proto_len != strlen (x11_proto) ||
	    memcmp (conn_head.cstr () + 12, x11_proto, proto_len) != 0) {
	  warn ("X11 connection uses different authentication protocol\n");
	  sbp->replyref (false);
          abort ();
	  return;
	}

	/* Check if authentication data matches our fake data. */
	if (data_len != x11_data_len ||
	    memcmp (conn_head.cstr () + 12 + ((proto_len + 3) & ~3),
		    x11_fake_data, x11_data_len) != 0) {
	  warn ("X11 auth data does not match fake data.");
	  sbp->replyref (false);
          abort ();
	  return;
	}
	
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	char *buf = (char *)xmalloc (chlen);
	memcpy (buf, conn_head.cstr (), chlen);
	memcpy (buf + 12 + ((proto_len + 3) & ~3),
		x11_real_data, x11_data_len);
	
	cookie_replaced = true;
	paios_out << str (buf, chlen);
	free (buf);
      }
    }
    sbp->replyref (true);
  }

  
};

struct xauthfd : public rexfd {  
  xauthfd (rexchannel *pch, int fd, str xauthcmd) : rexfd (pch, fd) {
    static bool garbage_bool;
    rex_payload arg;
    arg.channel = channo;
    arg.fd = fd;
      
    arg.data.set (const_cast<char *> (xauthcmd.cstr ()), xauthcmd.len ());

    proxy->call (REX_DATA, &arg, &garbage_bool,
		 aclnt_cb_null);

    arg.data.set (NULL, 0);
    proxy->call (REX_DATA, &arg, &garbage_bool,
		 aclnt_cb_null);
  }
};

class xauthchannel : public rexchannel {
  str xauthcmd;
  cbv::ptr xauthdone_cb;
  
  str xauthcmdline (str rdisplay, const char *protocol, const char *hexcookie)
  {
    return strbuf ("add %s %s %s\n", rdisplay.cstr (), protocol, hexcookie);
  }

  vec<str> authcmd () {
    vec<str> cmd;
    cmd.push_back ("xauth");	// Sic.  PATH_XAUTH might be wrong on server
    return cmd;
  }

public:
  xauthchannel (rexsession *sess, str rdisplay, const char *protocol,
		const char *hexcookie, cbv xauthdone_cb)
	       : rexchannel::rexchannel (sess, 1, authcmd ()),
		 xauthcmd (xauthcmdline (rdisplay, protocol, hexcookie)),
		 xauthdone_cb (xauthdone_cb)
  {}

  ~xauthchannel () {
    if (xauthdone_cb)
      xauthdone_cb ();
  }

  void madechannel (int error) {
    if (error) {
      warn << "failed to run xauth on server\n";
      sess->remove_chan (channo);
    }
    else
      vNew refcounted<xauthfd> (this, 0, xauthcmd);
  }
};


class xsocklistenfd : public rexfd {
  bool isunix;

  //isunix == false
  struct in_addr displayhost;
  u_int16_t displayport;

  //isunix == true
  str unixpath;
  
  str rdisplay;
  bool gotrdisplay;
  cbv::ptr xfreadycb;

  size_t x11_data_len;
  char *x11_real_data;
  char *x11_fake_data;
  char x11_proto[512];
  
  void
  tcpconnected (svccb *sbp, int fd) {	
    if (fd < 0) {
      warn << "X port forward connection to localhost:" << displayport <<
	" failed: " << strerror (errno);
      sbp->replyref (false);
      return;
    }
    tcp_nodelay (fd);
    
    rexcb_newfd_arg *parg = sbp->Xtmpl getarg<rexcb_newfd_arg> ();
    vNew refcounted<xclientfd> (pch, parg->newfd, fd, x11_real_data,
				x11_fake_data, x11_data_len,
				implicit_cast<char *> (x11_proto));
    if (opt_verbose)
      warn << "X forwarding channel created\n";
    sbp->replyref (true);
  }

  // returns display number if unix domain display, otherwise -1
  static int xconninfo_unix (const char *display) {
    int displaynum;
    
    if (!display)
      return -1;

    char *ocolon = strrchr (display, ':');
    if (!ocolon)
      return -1;
    
    if (display[0] == ':' || !strncmp (display, "unix:", 5)) {
      if (sscanf(ocolon + 1, "%d", &displaynum) != 1)
	return -1;
      return displaynum;
    }
    
    return -1;
  }
  
  // returns 1 on success, -1 on failure
  static int xconninfo_tcp (const char *display, struct in_addr &pia,
			    u_int16_t &port) {
    if (!display)
      return -1;

    char *ocolon = strrchr (display, ':');
    if (!ocolon || ocolon < (display + 1))
      return -1;
    
    str hostname (display, ocolon - display);
    struct hostent *ph;
    
    if ((ph = gethostbyname (hostname.cstr ())) &&
	sscanf (ocolon + 1, "%hu", &port) == 1) {
      port += 6000;
      pia = * (struct in_addr *) (ph->h_addr);
      return 1;
    }
    else
      return -1;
  }
  
  
public:
  xsocklistenfd (rexchannel *pch, const char *display,
		 cbv xfreadycb = cbv_null) : rexfd (pch, 0), rdisplay (""),
					     gotrdisplay (false),
					     xfreadycb (xfreadycb) {
    int displaynum;
    if ((displaynum = xconninfo_unix (display)) >= 0) {
      isunix = true;
      unixpath = strbuf () << XPREFIX << displaynum;
    }
    else if (xconninfo_tcp (display, displayhost, displayport) > 0)
      isunix = false; 
  }

  void
  newfd (svccb *sbp) {
    rexcb_newfd_arg *parg = sbp->Xtmpl getarg<rexcb_newfd_arg> ();
      
    if (isunix) {
      int fd = unixsocket_connect (unixpath.cstr ());
      if (fd < 0) {
	warn << "X port forward connection to localhost:" << displayport <<
	  " failed: " << strerror (errno);
	return;
      }
      else {
	vNew refcounted<xclientfd> (pch, parg->newfd, fd, x11_real_data,
				    x11_fake_data, x11_data_len,
				    implicit_cast<char *> (x11_proto));
	if (opt_verbose)
	  warn << "X forwarding channel created\n";
	sbp->replyref (true);
      }
    }
    else
      tcpconnect (displayhost, displayport,
		  wrap(this, &xsocklistenfd::tcpconnected, sbp));
  }

  void
  mkauthchannel (clnt_stat) {
    //XXX: replace these arrays with str's, w/o hardcoded length
    char line[512];
    char data[512];
    char fake_data[512];
    
    FILE *f;
    
    snprintf (line, sizeof (line), "%s list %.200s", 
	      PATH_XAUTH, getenv("DISPLAY"));
    f = popen (line, "r");
    if (f && fgets (line, sizeof (line), f) &&
	sscanf (line, "%*s %s %s", x11_proto, data) == 2) {
      if (opt_verbose)
	warn << "got xauth info\n";
    }
    else {
      //if client side doesn't support xauth, fill in with junk, it will ignore
      strcpy (x11_proto, "MIT-MAGIC-COOKIE-1");
      for (int ix = 0; ix < 32; ix++)
	data[ix] = '0';
      data[32] = NULL;
    }
    if (f)
      pclose (f);

    size_t data_len = strlen (data) / 2;

    x11_fake_data = (char *) xmalloc(data_len);
    rnd.getbytes (x11_fake_data, data_len);

    x11_real_data = (char *) xmalloc (data_len);
    for (u_int i = 0; i < data_len; i++) {
      u_int32_t value;
      if (sscanf (data + 2 * i, "%2x", &value) != 1)
	fatal("x11_request_forwarding: bad authentication data: %.100s", data);
      x11_real_data[i] = value;

      //x11_fake_data to string so it can be installed on server with xauth cmd
      sprintf (fake_data + 2 * i, "%02x", (u_char) x11_fake_data[i]);
    }
    x11_data_len = data_len;

    sess->makechannel (New refcounted <xauthchannel>(::sess, rdisplay, 
						       x11_proto, fake_data, 
						       xfreadycb));
    // xfreadycb = NULL;
  }

  void
  data (svccb *sbp) {
    rex_payload *argp = sbp->Xtmpl getarg<rex_payload> ();

    // length w/o newline
    size_t lenwonl = argp->data.size ();
    if (!lenwonl) {
      // let rexfd handle eof
      rexfd::data (sbp);
      return;
    }

    // ignore anything after DISPLAY has been sent
    if (gotrdisplay) {
      sbp->replyref (true);
      return;
    }

    if (argp->data.base ()[lenwonl - 1] == '\n') {
      lenwonl--;
      gotrdisplay = true;
    }

    rdisplay = strbuf () << rdisplay << str (argp->data.base (), lenwonl);

    if (gotrdisplay) {
      rex_setenv_arg arg;
      arg.name = str ("DISPLAY");
      arg.value = rdisplay;
      proxy->call (REX_SETENV, &arg, &garbage_bool,
		   wrap (this, &xsocklistenfd::mkauthchannel));
    }
    sbp->replyref (true);
  }

};

class xfchannel : public rexchannel {

  const char *display;
  cbv::ptr xfreadycb;

  vec<str> xcommand () {    
    vec<str> cmd;
    cmd.push_back ("listen");
    cmd.push_back ("-x");
    return cmd;
  }
  
public:
  xfchannel (rexsession *sess, const char *display, cbv xfreadycb = cbv_null):
	    rexchannel (sess, 1, xcommand ()),
	    display (display), xfreadycb (xfreadycb) {}

  void madechannel (int) {
    vNew refcounted<xsocklistenfd> (this, display, xfreadycb);
    // xfreadycb = NULL;
  }

  void
  exited (int status) {
    // Check to make sure really an error and not just
    // the end of the connection
    if (status < 0)
      warn << "Could not set up X-forwarding (listen caught "
	   << "signal " << -status << ").\n";
    else if (status > 0)
      warn << "Could not set up X-forwarding (listen exited "
	   << "with status = " << status << ").\n";

    rexchannel::exited (status);

    if (xfreadycb && status != 0) {
      warn << "Disabling X-forwarding and continuing.\n";
      xfreadycb ();
    }
  }
};

class binmodulechannel : public rexchannel {

  str local;
  str remote;
  vec<int> pfds;
  cbv::ptr modulereadycb;
  
  vec<str> cmd2vec (str cmdstr) {
    char *cmd = const_cast<char *> (cmdstr.cstr ());
    vec<str> cmdvec;
    char *word, *sep = "\t ";
    for (word = strtok(cmd, sep); word; word = strtok(NULL, sep))
      cmdvec.push_back (word);
    return cmdvec;
  }
  
public:
  binmodulechannel (rexsession *sess, str localcmd, str remotecmd,
		    cbv::ptr modulereadycb = NULL)
    : rexchannel (sess, 3, cmd2vec (remotecmd)), local (localcmd),
      remote (remotecmd), modulereadycb (modulereadycb)
  {
    vec<str> localargs = cmd2vec (localcmd);
    if (!localargs.size ()) {
      fatal << "null module command specified, ignoring\n";
      return;
    }
    str s = find_program_plus_libsfs (localargs[0]);
    if (!s) {
      fatal << "Could not locate program: " << localargs[0] << "\n";
      return;
    }

    vec<char *> av;
    for (u_int i = 0; i < localargs.size (); i++)
      av.push_back (const_cast<char *> (localargs[i].cstr ()));
    av.push_back (NULL);
    
    vec<int> cfds;
    for (int ix = 0; ix <= 2; ix++) {
      int socks[2];
      if (socketpair (AF_UNIX, SOCK_STREAM, 0, socks) < 0) {
	warn ("failed to create socketpair for local module: %m\n");
	return;
      }
      close_on_exec (socks[0]);
      pfds.push_back (socks[0]);
      cfds.push_back (socks[1]);
    }

    aspawn (s, av.base (), cfds[0], cfds[1], cfds[2]);
    for (int i = 0; implicit_cast<unsigned> (i) < cfds.size (); i++)
      close (cfds[i]);	
  }

  void madechannel (int error) {
    if (!error && pfds.size () == 3) {	  
      vNew refcounted<unixfd> (this, 0, pfds[0], -1, false, true);
      vNew refcounted<unixfd> (this, 1, pfds[1], -1, false, true);
      vNew refcounted<unixfd> (this, 2, pfds[2], -1, false, true);
    }

    if (modulereadycb) {
      modulereadycb ();
      modulereadycb = NULL;
    }
  }
};

void
create_interactive_chan (ref<int> pfchanleft, vec<str> command) 
{
  if (--*pfchanleft <= 0) {
    vec<rex_envvar> env;
    rex_env renv;

    if (opt_noX)
      env.push_back (strbuf () << "!DISPLAY");  // proxy will see ! and
						// eliminate var from environ
    if (opt_notty) {
      renv.set (env.base (), env.size ());
      sess->makechannel (New refcounted <execchannel> (sess, command), renv);
    } else {
      if (char *term = getenv ("TERM"))
	env.push_back (strbuf () << "TERM=" << term);
      renv.set (env.base (), env.size ());
      sess->makechannel (New refcounted <ttychannel> (sess, command), renv);
    }
  }
}

void
create_interactive_chan_acb (ref<int> pfchanleft, vec<str> command,
			     clnt_stat err) {
  create_interactive_chan (pfchanleft, command);
}

void connect (bool force);
void connect_nocache ();
time_t reconnect_time;
time_t retry_delay;

void
reconnect (bool force)
{
  if (opt_verbose)
    warn << (force ? "" : "possibly ") << "reconnecting\n";

  reconnect_time = timenow;

  if (!force) {
    ptr<bool> res = aconn->keepalive (schost);
    if (!res)
      fatal << "couldn't connect to agent";
    if (!*res)
      fatal << "agent's connection failed";

    if (sess->last_heard > reconnect_time) {
      if (opt_resumable) {
        sess->silence_tmo_reset ();
        sess->silence_tmo_enable ();
      }
      return;
    }
  }

  retry_delay = 0;
  connect (force);
}

bool
timeout ()
{
  if (opt_verbose)
    warn << "connection is unresponsive\n";
  reconnect (false);
  return true;
}

bool
failed ()
{
  if (opt_verbose)
    warn << "rex connection failed\n";
  if (opt_resumable) {
    reconnect (true);
    return true;
  }
  else {
    exit (1);
    return false;
  }
}

void
make_session (ref<sfsagent_rex_res> ares)
{
  vec<char> secretid;
  rex_mksecretid (secretid, ares->resok->ksc, ares->resok->kcs);
  // rpc_wipe (ares); XXX?

  sess = New rexsession (schost, proxyxprt, secretid, wrap (failed),
                         opt_resumable ? wrap (timeout) : NULL,
                         opt_verbose, opt_resumable);

  ref<int> left = New refcounted<int> (modules.size ());
 
  char *display = getenv ("DISPLAY");
  if (!display && !opt_noX) {
    warn << "DISPLAY environment variable is not set..."
	 << "disabling X forwarding\n";
    opt_noX = true;
  }
  if (!opt_noX) {
    rndaskcd ();
    ++*left;
    sess->makechannel
      (New refcounted<xfchannel> (sess, display, wrap (create_interactive_chan,
						       left, command)));
  }

  if (!*left) {
    create_interactive_chan (left, command);
    return;
  }
  
  for (int ix = 0; implicit_cast<size_t> (ix) < modules.size (); ix++)
    sess->makechannel
      (New refcounted<binmodulechannel> (sess, modules[ix].local,
					 modules[ix].remote,
					 wrap (create_interactive_chan,
					       left, command)));
}

void
resumed_session (bool success)
{
  if (!success)
    fatal << "couldn't resume session\n";
}

void
attached (ref<rexd_attach_res> resp, ptr<axprt_crypt> sessxprt,
          ref<sfsagent_rex_res> ares, clnt_stat err)
{
  if (err) {
    fatal << "FAILED (" << err << ")\n";
  }
  else if (*resp != SFS_OK) {
    warn << "Unable to attach to proxy (err " << int (*resp) << ")\n"
	 << "killing cached connection and retrying.\n";
    sfsc = NULL;

    connect_nocache ();
    return;
  }
  if (opt_verbose)
    warn << "attached\n";
    
  proxyxprt = axprt_crypt::alloc (sessxprt->reclaim ());
  proxyxprt->encrypt (ares->resok->kcs.base (),
		      ares->resok->kcs.size (),
		      ares->resok->ksc.base (),
		      ares->resok->ksc.size ());
    
  if (sess) {
    if (opt_verbose)
      warn ("resuming rex session\n");
    sess->resume (proxyxprt, orig_seqno, wrap (resumed_session));
    // rpc_wipe (ares); XXX?
  }
  else
    make_session (ares);
}

timecb_t *
backoff (time_t &delay, time_t initdelay, time_t maxdelay, cbv::ref cb)
{
  timecb_t *tcb = delaycb (delay, cb);
  delay = delay ? min<time_t> (delay * 2, maxdelay) : initdelay;
  return tcb;
}

void
connected (ref<sfsagent_rex_res> ares, bool force, ptr<sfscon> sc, str err)
{
  if (!force && sess && sess->last_heard > reconnect_time) {
    sess->silence_tmo_reset ();
    sess->silence_tmo_enable ();
    return;
  }

  if (!sc) {
    if (sfsc && opt_resumable) {
      if (opt_verbose)
        warn << schost << ": failed (" << err << "); retrying\n";
      backoff (retry_delay, 10, 60, wrap (reconnect, force));
    }
    else {
      fatal << schost << ": failed (" << err << ")\n";
    }
    return;
  }
  assert (!err);

  if (sc == sfsc) {
    if (opt_verbose)
      warn << "no need to reconnect\n";
    if (sess && opt_resumable) {
      sess->silence_tmo_reset ();
      sess->silence_tmo_enable ();
    }
    return;
  }
  sfsc = sc;

  ptr<axprt_crypt> sessxprt = sc->x;
  ptr<aclnt> sessclnt = aclnt::alloc (sessxprt, rexd_prog_1);

  rexd_attach_arg arg;
    
  arg.sessid = ares->resok->sessid;
  arg.seqno = ares->resok->seqno;
  arg.newsessid = ares->resok->newsessid;

  ref<rexd_attach_res> resp (New refcounted<rexd_attach_res>);
  sessclnt->call (REXD_ATTACH, &arg, resp,
                  wrap (attached, resp, sessxprt, ares));
}

void
connect (bool force)
{
  bool rex_forwardagent = opt_forwardagent && !sess;
  bool rex_blockactive = sess;
  bool rex_resumable = opt_resumable && !sess;

  ptr<sfsagent_rex_res> ares = aconn->rex (dest, schost, rex_forwardagent,
                                           rex_blockactive, rex_resumable);
  if (!ares)
    fatal << "could not connect to agent\n";
  if (!ares->status)
    fatal << "agent failed to establish a connection to "
	  << schost << ".\n"
	  << "     Perhaps you don't have permissions to login there.\n"
	  << "     Perhaps you don't have any keys loaded in your agent.\n"
	  << "     Perhaps the remote machine is not running a REX server.\n";

  seqno = ares->resok->seqno;
  if (!sess)
    orig_seqno = seqno;

  sfs_connect_cb ccb = wrap (connected, ares, force);
  if (sfsc)
    sfs_reconnect (sfsc, ccb, force);
  else
    sfs_connect_path (schost, SFS_REX, ccb, false);
}

void
connect_nocache ()
{
  sfs_hostname arg = schost;
  bool res;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_KILLSESS, &arg, &res))
    fatal << "agent: " << err << "\n";
  if (!res)
    fatal << "no rexsessions connected to " << schost << "\n";

  connect (true);
}

static void
dest_addkey_to_agent (sfskey *k)
{
  if (opt_verbose)
    warn << "adding key to agent: " << k->keyname << "\n";

  sfs_addkey_arg arg;
  if (!k->key || !k->key->export_privkey (&arg.privkey))
    fatal << "could not fetch private key via SRP\n";

  arg.expire = 0;
  arg.name = k->keyname;
  bool res;

  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_ADDKEY, &arg, &res))
    fatal << "agent: " << err << "\n";
  else if (!res)
    warn << "agent refused private key\n";
}

static str
dest_srpname_lookup (str srpname, sfskey *k, ptr<sfscon> *sc, 
		     ptr<sfsauth_certinfores> *ci)
{
  if (opt_verbose)
    warn << "fetching key via SRP: " << srpname << "\n";

  sfsagent_srpname namearg = srpname;
  sfsagent_srpname_res nameres;
  
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_LOOKUPSRPNAME, &namearg, &nameres))
    fatal << "agent: " << err << "\n";
  if (nameres.status) {
    if (opt_verbose)
      warn << "SRP cache lookup in agent succeeded: " 
	   << *nameres.sfsname << "\n";
    *sc = NULL;
    return *nameres.sfsname;
  }

  if (str err = sfskeyfetch (k, srpname, sc, ci))
    fatal << "error fetching key: " << err << "\n";
  if (!*sc)
    fatal << "Invalid connection to authserver.\n";

  sfsagent_srpname_pair pairarg;
  bool pairres;

  pairarg.srpname = srpname;
  pairarg.sfsname = (*sc)->path;
  if (clnt_stat err = 
      aconn->cagent_ctl ()->scall (AGENTCTL_ADDSRPNAME, &pairarg, &pairres))
    fatal << "agent: " << err << "\n";
  else if (!pairres)
    fatal << "could not cache self-certifying hostname from SRP\n";

  return (*sc)->path;
}

static str
dest_pathname_lookup (str dest, int *err)
{
  str sfs_schost;
  int sfs_scherr = path2sch (dest, &sfs_schost);

  if (sfs_scherr)
    *err = sfs_scherr;

  if (!sfs_schost || !sfs_schost.len ())
    return NULL;
  else
    return sfs_schost;
}

static str
parse_destination (str dest)
{
  char *at;
  char *comma;

  /* if dest doesn't contain '@' then try to lookup it up with the agent */
  if (!(at = strchr (dest, '@'))) {
    int err;
    str s = dest_pathname_lookup (dest, &err);
    if (s) {
      return s;
    }
    else if (!strchr (dest, '/') && !strchr (dest, ',')) {
#if 0
      if (!opt_quiet)
	warn << "Prepending '@' to destination `" << dest
	  << "' and attempting SRP\n";
#endif
      dest = strbuf () << "@" << dest;
    }
    else {
      warn << "Could not resolve self-certifying hostname from " 
	   << dest << ".\n";
      fatal << "Lookup returned: " << strerror (err) << "\n";
    }
  }

  /* if dest has a ',' assume its self-certifying */
  if ((comma = strchr (dest, ','))) {
    if (sfs_parsepath (at))
      return strbuf () << at;
    else
      fatal << "cannot parse self-certifying hostname `" << dest << "'\n";
  }

  /* if dest doesn't have a ',' use SRP */
  str user;
  str host;
  if (dest[0] == '@')
    dest = substr (dest, 1);
  if (!parse_userhost (dest, &user, &host))
    fatal << dest << " contains an `@' but not of form user@hostname\n";
  str srpname = strbuf () << user << "@" << host;
  str sfsname;

  sfskey k;
  ptr<sfscon> sc;
  ptr<sfsauth_certinfores> ci;

  agent_spawn (opt_verbose);
  sfsname = dest_srpname_lookup (srpname, &k, &sc, &ci);
  if (sc)
    dest_addkey_to_agent (&k);

  if (ci && ci->info.status == SFSAUTH_CERT_REALM)
    warn << "NOTE: authserver is in realm " << ci->name << "\n";
  return sfsname;
}

static void
usage ()
{
  fatal << "usage: " << progname << " [options] destination [command]\noptions:\n"
	<< "-T                              Disable pseudo-tty allocation\n"
	<< "-t                              Force pseudo-tty allocation\n"
	<< "-A                              Disable SFS agent forwarding\n"
	<< "-x                              Disable X11 forwarding\n"
        << "-r                              Resume session if disconnected\n"
	<< "-v                              Verbose\n"
	<< "-q                              Quiet\n"
	<< "-l user                         Ignored; for rsh/ssh compatibility\n"
	<< "-o option                       Ignored; for ssh compatibility\n"
	<< "-m client_mod server_mod        Module support\n"
	<< "\n"
	<< "destination is one of the following:\n"
	<< "  * a DNS hostname              [user]@hostname (uses SRP)\n"
	<< "  * a self-certifying hostname  @hostname,hostid\n"
	<< "  * a SFS nickname              hostname\n"
	<< "                                (uses agent to resolve; falls back to SRP)\n"
    //	<< "  * a self-certifying pathname (/sfs/... or /symlink-to-sfs/...)\n"
    //	<< "  * any identifier which when processed through certification programs\n"
    //	<< "	will yield a self-certifying pathname\n"
	<< "\n";
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);
  putenv ("POSIXLY_CORRECT=1");	// Prevents Linux from reordering options
  sfsconst_init ();

  int ch;
  
  while ((ch = getopt (argc, argv, "Avm:Ttxl:o:qr")) != -1)
    switch (ch) {
    case 'A':
      opt_forwardagent = false;
      break;
    case 'm':
      {
	module_pair mp;
	if (optind < argc - 1 && argv[optind][0] != '-') {
	  mp.local = optarg;
	  mp.remote = argv[optind];
	  modules.push_back (mp);
	  optind++;		    //skip over second argument
	}
	else
	  usage ();
	break;
      }
    case 'T':
      if (opt_tty) {
	warn << "-T and -t are mutually exclusive\n";
	usage ();
      }
      opt_notty = true;
      break;
    case 't':
      if (opt_notty) {
	warn << "-T and -t are mutually exclusive\n";
	usage ();
      }
      opt_tty = true;
      break;
    case 'v':
      opt_verbose = true;
      break;
    case 'x':
      opt_noX = true;
      break;
    case 'q':
      opt_quiet = true;
      break;
    case 'l':
    case 'o':
      // Ignored; for rsh/ssh compatibility
      break;
    case 'r':
      opt_resumable = true;
      break;
    default:
      usage ();
    }
  argc -= optind;
  argv += optind;

  if (argc < 1)
    usage ();

  aconn = New refcounted<agentconn> ();
  dest = argv[0];
  schost = parse_destination (dest);
  if (!opt_quiet)
    warn << "Connecting to " << schost << "\n";

  if (!isatty (STDIN_FILENO)) {
    if (opt_tty)
      warn << "Ignoring -t flag (force pseudo-tty allocation) "
	   << "because stdin is not a terminal\n";
    opt_notty = true;
  }
    
  if (argc == 1) {
    //special value signifying default shell
    command.push_back (".");
  }
  else {
    /* if a command is specified, don't allocate a tty by default */
    if (!opt_tty)
      opt_notty = true;
    for (int i = 1; i < argc; i++)
      command.push_back (argv[i]);
  }

  connect (true);
  sigcb (SIGUSR1, wrap (simulateeof));
  amain ();
}
