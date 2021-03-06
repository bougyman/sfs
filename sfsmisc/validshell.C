/* $Id: validshell.C,v 1.2 2003/01/28 04:19:44 dm Exp $ */

/*
 *
 * Copyright (C) 2003 David Mazieres (dm@uun.org)
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

extern "C" {
  char *getusershell(void);
  void setusershell(void);
  void endusershell(void);
}

bool
validshell (const char *shell)
{
  const char *s;

  setusershell ();
  while ((s = getusershell ()))
    if (!strcmp(s, shell)) {
      endusershell ();
      return true;
    }
  endusershell ();
  return false;
}

