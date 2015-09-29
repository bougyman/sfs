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
 * btd_prot.h - a description of the protocol used to communicate between
 *              the btree daemon and clients
 */


/*
 * if NEW_CONNECTION is received on the FIFO, don't process it as
 * a request at offset 0, it signals instead that a new client
 * is registering itself with the daemon. It will next send a 2 byte
 * packet length, a character string representing a path to it's fifo
 * which we will use to notify it of completion, and it's PID
 */
#define NEW_CONNECTION 0
#define END_CONNECTION 1

/*
 * Operations - the first 2 bytes of the request in shared mem are the 
 *              requested operation
 */ 

#define OP_SEARCH 1
#define OP_INSERT 2
#define OP_DELETE 3
#define OP_ITERATE 4
#define OP_FINALIZE 5

struct request_t {
  pid_t pid;
  long offset;
};


