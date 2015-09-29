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
 * NodeStorage.h -- a nodeStorage object abstracts a block of core memory
 *                  used to hold the node. It could be an aiobuf, or just
 *                  a void *.
 *
 *               (this version will use aiobuf's)
 */

#ifndef _NODE_STORAGE_H_
#define _NODE_STORAGE_H_

#include <aiod.h>
#ifdef HAVE_AIO_H
#include <aio.h>
#endif
#include "sysconf.h"
#include <refcnt.h>

class nodeStorage {

 public:
  void *base() {
    return buf->base();
  };

  ptr<aiobuf> abuf() {
    return buf;
  }

  long size() {
    return buf->size();
  }
  
  nodeStorage(ptr<aiobuf> Buf) {
    buf = Buf;
  }

  ~nodeStorage() {
   
  }

 private:
  
  ptr<aiobuf> buf;
};

#endif
