/* $Id: ttyd.C,v 1.19 2004/01/13 02:13:29 dbg Exp $ */

/*
 *
 * Copyright (C) 2001 Eric Peterson (ericp@lcs.mit.edu)
 * Copyright (C) 2001 Michael Kaminsky (kaminsky@lcs.mit.edu)
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

#include "sfsmisc.h"
#include "crypt.h"
#include "aios.h"
#include "rex_prot.h"
#include "sfstty.h"

ptr <aios> paios;

/* from openssh  */
/* Changes the window size associated with the pty. */

static void
pty_change_window_size(int ptyfd, int row, int col,
		       int xpixel, int ypixel)
{
  struct winsize w;
  w.ws_row = row;
  w.ws_col = col;
  w.ws_xpixel = xpixel;
  w.ws_ypixel = ypixel;
  (void) ioctl (ptyfd, TIOCSWINSZ, &w);
}

void
windowresize (int mfd, const str data, int err)
{
  static int x = 0;
  static int a[4];

  if (!data || !data.len ()) {
    warn << "proxy died; exiting\n";
    exit (1);
  }

  //todo: use something better than atoi
  a[x++] = atoi (data.cstr());

  if (x == 4) {
    //do resize
    pty_change_window_size (mfd, a[0], a[1], a[2], a[3]);
    //warn ("changing window size to col:%d  row:%d  xpix:%d  ypix:%d\n",
    //	  a[1], a[0], a[2], a[3]);
	  
    x = 0;
  }

  paios->readline (wrap (windowresize, mfd));
}

static void
slaveexit (int status)
{
  /* Linux has problems flushing data, so sleep for a tiny bit of time. */
#ifdef __linux__
  struct timeval t;
  t.tv_sec = 0;
  t.tv_usec = 100;
  select (0, NULL, NULL, NULL, &t);
#endif /* __linux */

  exit (WIFEXITED (status) ? WEXITSTATUS (status) : -WTERMSIG (status));
}

static void
postforkcb (str path)
{
  setsid ();
    
  int ttyfd = open (path, O_RDWR);
  if (ttyfd < 0)
    fatal << "could not open slave tty\n";

  dup2 (ttyfd, 0);
  dup2 (ttyfd, 1);
  dup2 (ttyfd, 2);

  if (ttyfd > 2)
    close (ttyfd);

#ifdef TIOCSCTTY
  //make us controlling terminal
  ioctl (0, TIOCSCTTY);
#endif /* TIOCSCTTY */
    
  //todo: set terminal modes here
}

void
usage ()
{
  fatal ("usage: %s utmp-hostname command [ command-arg ... ]\n",
         progname.cstr ());
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);
  sfsconst_init ();  

  if (argc < 3)
    usage ();

  warn ("ttyd called for utmp host: %s\n", argv[1]);

  /* Set up the command that we want to run. */
  str command;

  if (!strcmp (argv[2], ".")) {
    char *default_shell = getenv ("SHELL");
    if (default_shell)
      command = default_shell;
    else {
      warn ("SHELL not set, reverting to sh\n");
      command = "sh";
    }
  }
  else
    command = argv[2];

  command = find_program (command);
  if (!command)
    fatal << "Could not locate program: " << argv[2] << "\n";

  char *name = strdup (strrchr (command.cstr (), '/'));
  assert (name);
  /* If the shell is interactive, make it a login shell */
  if (argc == 3)
    *name = '-';
  else
    name++;

  /* Set up tty/pty. */
  int fd = suidgetfd_required ("ptyd");
  if (fd < 0)
    fatal << "connection to ptyd failed\n";

  ref<axprt_unix> ux = axprt_unix::alloc (fd);
  ref<aclnt> ac = aclnt::alloc (ux, ptyd_prog_1);

  utmphost host = argv[1];
  pty_alloc_res res;
  if (ac->scall (PTYD_PTY_ALLOC, &host, &res) || res.err) {
    fatal << "could not allocate pty via ptyd\n";
  }

  ttypath path = *res.path;	/* path to slave side of pseudo-tty */
  int mfd = ux->recvfd ();	/* fd connect to master side of pseudo-tty */
  if (mfd < 0)
    fatal << "could not receive master fd from ptyd\n";

  close_on_exec (mfd);
  close_on_exec (fd);
  
  /* Note that on *BSD, many things cannot be done to the pty file
   * descriptor until the tty has been opened.  For example, the pty
   * cannot even be put into non-blocking mode.  We therefore want to
   * make sure the shell has been executed before passing the pty file
   * descriptor back to proxy. */
  argv[2] = name;
  pid_t pid = spawn (command, &argv[2], 0, 1, 2, wrap (postforkcb, path));
  if (pid == -1)
    fatal << "could not fork\n";

  if (writefd (0, "", 1, mfd) < 0)
    fatal << "could not pass master fd to proxy\n";

  //keep mfd around for window resizing
  paios = aios::alloc (0);
  paios->readline (wrap (windowresize, mfd));
    
  chldcb (pid, wrap (slaveexit));
    
#if 0
  //is this necessary, will ptyd clean then up when master/slave fd closes ??

  //this has to be written async and put in slaveexit if it's necessary
    
  int err;
  if(ac->scall (PTYD_PTY_FREE, &path, &err) || err)
    warn("failed to free pty via ptyd\n");
#endif

  amain ();
}
