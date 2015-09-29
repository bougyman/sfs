/* $Id: sfskey.C,v 1.96 2004/05/14 23:46:03 max Exp $ */

/*
 *
 * Copyright (C) 1999 David Mazieres (dm@uun.org)
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
#include "srp.h"

bool opt_verbose;
bool opt_quiet;
ref<agentconn> aconn = New refcounted<agentconn> ();

void
nularg (int argc, char **argv)
{
  if (getopt (argc, argv, "") != -1 || optind < argc)
    usage ();
}

void
sfskey_kill (int argc, char **argv)
{
  nularg (argc, argv);
  if (aconn->ccd (false)) {
    int res;
    if (clnt_stat err = aconn->ccd ()->scall (AGENT_KILL, NULL, &res))
      fatal << "sfscd: " << err << "\n";
    else if (res)
      fatal << "sfscd: " << strerror (res) << "\n";
  }
  else if (clnt_stat err = aconn->cagent_ctl ()->scall (AGENTCTL_KILL,
							NULL, NULL))
    if (err != RPC_CANTRECV)
      fatal << "agent: " << err << "\n";
  exit (0);
}

void sfskey_help (int argc, char **argv);
struct modevec {
  const char *name;
  void (*fn) (int argc, char **argv);
  const char *usage;
};
const modevec modes[] = {
  { "add", sfskey_add,
    "add [-t [hrs:]min] [keyfile | [user]@authservhostname]" },
  { "certclear", sfskey_certclear, "certclear" },
  { "certlist", sfskey_certlist, "certlist [-q]" },
  { "certprog", sfskey_certprog,
    "certprog [-p prefixpath] [-f filter] [-e exclude] prog [arg ...]"},
  { "confclear", sfskey_confclear, "confclear" },
  { "conflist", sfskey_conflist, "conflist [-q]" },
  { "confprog", sfskey_confprog, "confprog prog [arg ...]" },
  { "delete", sfskey_delete, "delete keyname" },
  { "del", sfskey_delete, NULL },
  { "deleteall", sfskey_clear, "deleteall" },
  { "delall", sfskey_clear, NULL },
  { "edit", sfskey_edit,
    "edit [-LP] [-o outfile] [-c cost] [-l label] [keyname]" },
  { "gen", sfskey_gen, "gen [-KP] [-b nbits] [-c cost] [-l label] [keyname]" },
  { "generate", sfskey_gen, NULL },
  { "gethash", sfskey_gethash, "gethash [-6] keyname"},
  { "group", sfskey_group, "group [-a key] [-E] [-C] [-L version] "
    "[-m {+|-}membername] [-o {+|-}ownername] groupname" },
  { "help", sfskey_help, "help" },
  { "hostid", sfskey_hostid, "hostid [-s service] {hostname | -}" },
  { "kill", sfskey_kill, "kill" },
  { "list", sfskey_list, "list [-lq]" },
  { "login", sfskey_login, "login [-t [hrs:]min] [user@]hostname" },
  { "logout", sfskey_logout, "logout [user@]{host | realm}" },
  { "ls", sfskey_list, NULL },
  { "norevokeset", sfskey_norevokeset, "norevokeset hostid ... "},
  { "norevokelist", sfskey_norevokelist, "norevokelist"},
  { "passwd", sfskey_passwd, 
    "passwd [pK] [-S | -s srpfile] [-b nbits] [-c cost] [-l label]" },
  { "register", sfskey_reg,
    "register [-fgpPKS] [-b nbits] [-c pwdcost] [-u user] [-l label] "
    "[-w filename] [key]" },
  { "reg", sfskey_reg, NULL },
  { "reset", sfskey_reset, "reset" },
  { "revoke", sfskey_revoke, "revoke {certfile | -}" },
  { "revokegen", sfskey_revokegen, 
    "revokegen [-r newkeyfile [-n newhost]] [-o oldhost] oldkeyfile"},
  { "revokelist", sfskey_revokelist, "revokelist"},
  { "revokeclear", sfskey_revokeclear, "revokeclear"},
  { "revokeprog", sfskey_revokeprog,
    "revokeprog [-b [-f filter] [-e exclude]] prog [arg ...]"},
  { "select", sfskey_select, "select [-f] [key]"},
  { "sesskill", sfskey_sesskill, "sesskill remotehost" },
  { "sesslist", sfskey_sesslist, "sesslist [-q]"},
  { "srpgen", sfskey_srpgen, "srpgen [-b nbits] file" },
  { "srplist", sfskey_srplist, "srplist"},
  { "srpclear", sfskey_srpclear, "srpclear"},
  { "srpcacheprogclear", sfskey_srpcacheprogclear, "srpcacheprogclear" },
  { "srpcacheproglist", sfskey_srpcacheproglist, "srpcacheproglist [-q]" },
  { "srpcacheprog", sfskey_srpcacheprog, "srpcacheprog prog [arg ...]" },
  { "update", sfskey_update,
    "update [-fE] [-S | -s srp_parm_file] [-r srpkey] [-a oldkey] "
    "[-k newkey] server1 [server2 server3 ...]" },
  { "up", sfskey_update, NULL },
  { "user", sfskey_user, "user [ -a key ] username" },
  { "2edit", sfskey_2edit, 
    "2edit [-Emp] [-l label] [-S | -s srpfile] [key1] [key2] ... "},
  { "2gen", sfskey_2gen, 
    "2gen [-BEKP] [-u user] [-b nbits] [-c cost] [-a {server | -}]"
    "[-l label] [-k okeyname] [-S | -s srpfile] [-w wkeyname] [nkeyname]"},
  { NULL, NULL, NULL }
};

static const modevec *sfskey_mode;

void
usage ()
{
  if (!sfskey_mode)
    warnx << "usage: " << progname 
	  << " [-S sock] [-p pwfd] [-vq] command [args]\n"
	  << "	     " << progname << " help\n";
  else {
    while (!sfskey_mode->usage)
      sfskey_mode--;
    warnx << "usage: " << progname << " " << sfskey_mode->usage << "\n";
  }
  exit (1);
}

void
sfskey_help (int argc, char **argv)
{
  strbuf msg;
  msg << "usage: " << progname << " [-S sock] [-p pwfd] command [args]\n";
  for (const modevec *mp = modes; mp->name; mp++)
    if (mp->usage)
      msg << "	 " << progname << " " << mp->usage << "\n";
  make_sync (1);
  msg.tosuio ()->output (1);
  exit (0);
}

static void
sfskey_version ()
{
  strbuf msg;
  msg << "sfskey -- SFS version " << VERSION << "\n";
  make_sync (1);
  msg.tosuio ()->output (1);
  exit (0);
}


int
main (int argc, char **argv)
{
  setprogname (argv[0]);
  xputenv ("POSIXLY_CORRECT=1"); // Prevents Linux from reordering options
  sfsconst_init ();
  srp_base::minprimsize = sfs_mindlogsize;

  int ch;
  while ((ch = getopt (argc, argv, "S:p:vqV")) != -1)
    switch (ch) {
    case 'S':
      agentsock = optarg;
      break;
    case 'V':
      sfskey_version ();
      break;
    case 'p':
      {
	int fd;
	if (!convertint (optarg, &fd))
	  usage ();
	opt_pwd_fd = true;
	close_on_exec (fd);	// Paranoia
	pwd_fds.push_back (fd);
	break;
      }
    case 'v':
      opt_verbose = true;
      break;
    case 'q':
      opt_quiet = true;
      break;
    default:
      usage ();
      break;
    }
  if (optind >= argc)
    usage ();

  const modevec *mp;
  for (mp = modes; mp->name; mp++)
    if (!strcmp (argv[optind], mp->name))
      break;
  if (!mp->name)
    usage ();
  sfskey_mode = mp;

  optind++;

  mp->fn (argc, argv);
  amain ();
}

#ifdef XXX_EXIT
#undef exit
/* XXX - gcc-2.95.2 bug on alpha */
void
XXX_call_exit (int code)
{
  exit (code);
}
#endif /* XXX_EXIT */
