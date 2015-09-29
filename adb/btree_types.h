/*
 *
 * Copyright (C) 1999 Frank Dabek (fdabek@mit.edu)
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

/*
 * btree_types.h 
 *
 * definition of common types used by btree classes
 *
 */

typedef long nodeID_t;
typedef unsigned short localPtr_t;
typedef long bOffset_t;
typedef long bSize_t;
typedef unsigned short bLocalSize_t;
typedef long blockID_t;
typedef long bError_t;
typedef short bOp_t;
typedef long sArg_t;
typedef long tid_t;
typedef short bLock_t;

#define noErr 0
#define BERROR_PAGEFAULT 1
#define BERROR_NOTFOUND 2
#define BERROR_DUPKEY 3

#define OP_SEARCH 1
#define OP_INSERT 2
#define OP_DELETE 3
#define OP_ITERATE 4
#define OP_FINALIZE 5

#define kLeafTag 1
#define kIndexTag 2
#define kSegTag 3
#define kNone 127

#define bUnlocked 0
#define bLockRead 1
#define bLockWrite 2
#define bLockEx    4

