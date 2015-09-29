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
 * bAllocFF.h
 *
 * bAlloc manages the btree's free-list. This implementation uses the
 * first-fit algorithm to allocate memory. Blocks of memory may be
 * requested in any size that is a multiple of one byte.
 *
 * Based on "Algorithm B" from the dynamic storage allocation chapter
 * of "The Art of Computer Programming" by Knuth
 *    
 * REP: avail points to a doubly linked list of freeEntry records
 * which specify free blocks. The records in the linked list are
 * sorted in ascending order of address (i.e. by entry->base)
 */

#ifndef _BALLOCFF_H_
#define _BALLOCFF_H_

#include "btree_types.h"
#include "superBlock.h"

struct freeEntry {
  blockID_t base;
  bSize_t size;
  struct freeEntry *link;
  struct freeEntry *prev;
};

struct freeEntrySB {
  bSize_t base;
  bSize_t size;
};

struct allocatedEntry {
  bSize_t base;
  bSize_t id;
  long next;
  bSize_t size;
};

class bAllocFF {

 public:
  bAllocFF(superBlock *sb);
  ~bAllocFF();
  void initFreeMap(bOffset_t off);
  blockID_t alloc(bSize_t len);
  blockID_t alloc(blockID_t addr, bSize_t len);
  void dealloc(bOffset_t offset, bSize_t len);
  int preflightAllocation(bSize_t len);
  void expand();
  int compactOne(int *handle, blockID_t *newAddr);
  void doSwap(int handle, blockID_t newAddr);
  bSize_t minFileSize();
  void finalize() { updateSuperblock(); };

  blockID_t derefHandle(nodeID_t id);
  bSize_t nodeSize(nodeID_t id);
  void freeHandle(bOffset_t offset);
  blockID_t makeHandle(blockID_t addr, bSize_t size);
  void printRep();

 private:
  void removeEntry(freeEntry *Q);
  void addEntry(freeEntry *n, freeEntry *before);
  void allocateFromEntry(freeEntry *Q, bSize_t len);
  void initFromMap(char *map);
  void updateSuperblock();

  long currentManagedSize;
  superBlock *superBlck;

  freeEntry *avail;

  int numHandles;
  int maxHandles;
  allocatedEntry *sortedByID;
};

void createInitialSuperblock(char *map, bSize_t nodesize);  
#endif
