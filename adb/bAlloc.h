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
 * bAlloc.h
 *
 * bAlloc manages the btree's free-list. Much like a file-system the
 * tree requires a data structure to track which disk blocks are
 * available to hold nodes. bAlloc is used by nodeBuf and is not
 * likely to be used directly by users
 * 
 */
#ifndef _BALLOC_H_
#define _BALLOC_H_

#include "btree_types.h"
#include "bbuddy.h"
#include "superBlock.h"

struct alloc_ent {
  long offset;
  long len;
};

class bAlloc {

 public:
  bAlloc(superBlock *sb);
  ~bAlloc() { if (map) free(map); };
  void initFreeMap(bOffset_t off);
  blockID_t alloc(bSize_t len);
  void dealloc(bOffset_t offset, bSize_t len);
  char blockFree(blockID_t block);
  void markUsed(blockID_t block);
  void markFree(blockID_t b);
  int preflightAllocation(bSize_t lenInBlocks);
  void expand();

 private:
  char *map;
  long masks[8];
  long cursor;
  long mapLen;
  long size;

  long blocksFree;

  superBlock *superBlck;
};
  
#endif
