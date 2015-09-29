/* $Id: sfskey.h,v 1.66 2004/03/10 21:34:41 kaminsky Exp $ */

/*
 *
 * Copyright (C) 1999 David Mazieres (dm@uun.org)
 * Copyright (C) 1999 Michael Kaminsky (kaminsky@lcs.mit.edu)
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

#include "parseopt.h"
#include "crypt.h"
#include "agentmisc.h"
#include "agentconn.h"
#include "sfskeymisc.h"

#define RANDOM_SEED "~/.sfs/random_seed"

extern bool opt_verbose;
extern bool opt_quiet;
extern ref<agentconn> aconn;

#if __GNUC__ == 2 && __GNUC_MINOR__ <= 95 && defined (__alpha__)
# define XXX_EXIT 1
#endif /* gcc <= 2.95.x && alpha */

#ifdef XXX_EXIT
void XXX_call_exit (int code);
#define exit XXX_call_exit
#endif /* XXX_EXIT */

void usage () __attribute__ ((noreturn));
void nularg (int argc, char **argv);

void sfskey_2gen (int argc, char **argv);
void sfskey_2edit (int argc, char **argv);
void sfskey_add (int argc, char **argv);
void sfskey_certclear (int argc, char **argv);
void sfskey_certlist (int argc, char **argv);
void sfskey_certprog (int argc, char **argv);
void sfskey_confclear (int argc, char **argv);
void sfskey_conflist (int argc, char **argv);
void sfskey_confprog (int argc, char **argv);
void sfskey_clear (int argc, char **argv);
void sfskey_delete (int argc, char **argv);
void sfskey_edit (int argc, char **argv);
void sfskey_gen (int argc, char **argv);
void sfskey_gethash (int argc, char **argv);
void sfskey_group (int argc, char **argv);
void sfskey_hostid (int argc, char **argv);
void sfskey_sesskill (int argc, char **argv);
void sfskey_list (int argc, char **argv);
void sfskey_login (int argc, char **argv);
void sfskey_logout (int argc, char **argv);
void sfskey_passwd (int argc, char **argv);
void sfskey_sesslist (int argc, char **argv);
void sfskey_norevokelist (int argc, char **argv);
void sfskey_norevokeset (int argc, char **argv);
void sfskey_reg (int argc, char **argv);
void sfskey_reset (int argc, char **argv);
void sfskey_revoke (int argc, char **argv);
void sfskey_revokeclear (int argc, char **argv);
void sfskey_revokegen (int argc, char **argv);
void sfskey_revokelist (int argc, char **argv);
void sfskey_revokeprog (int argc, char **argv);
void sfskey_select (int argc, char **argv);
void sfskey_srpgen (int argc, char **argv);
void sfskey_srplist (int argc, char **argv);
void sfskey_srpclear (int argc, char **argv);
void sfskey_srpcacheprogclear (int argc, char **argv);
void sfskey_srpcacheproglist (int argc, char **argv);
void sfskey_srpcacheprog (int argc, char **argv);
void sfskey_update (int argc, char **argv);
void sfskey_user (int argc, char **argv);
