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

#include "config.h"
#include "bAllocFF.h"
#include "btree.h"
#include "stdlib.h"

#define kUnused -1

int compareFunc(const void *a, const void *b);

/* ------------- static ------------ */
void
createInitialSuperblock(char *map, bSize_t nodesize) {
  freeEntrySB *fesb = (freeEntrySB *)map;

  //init size of free list and total szie
  fesb[0].size = 1;
  fesb[0].base = 5000000; //5M
  //init the one (and only free record)
  fesb[1].base = nodesize + 1;
  fesb[1].size = fesb[0].base - nodesize;

  //init the allocated entry (the root node)
  allocatedEntry *ae = (allocatedEntry *)(map + sizeof(freeEntrySB)*2);
  //base holds num Handles
  ae[0].base = 1;
  //id holds max handles
  long maxHandles = ae[0].id = 100;
  //init the first entry
  ae[1].id = 1;
  ae[1].base = 1;
  ae[1].size = nodesize;
  ae[1].next = -1;

  for (int i = 2; i <= maxHandles; i++) {
    ae[i].id = kUnused;
    ae[i].base = RAND_MAX;
  }

}


/* ----------- end static --------------- */
bAllocFF::bAllocFF(superBlock *sb) {

  superBlck = sb;
  
  //initialize freelist from 'bitmap' in superblock
  char * fm = sb->freeMap();
  initFromMap(fm);
  
}

bAllocFF::~bAllocFF() {

  updateSuperblock();
  
}

void
bAllocFF::initFromMap(char *map) {
  freeEntrySB *fesb;
  freeEntry *cur = NULL, *prev;

  fesb = (freeEntrySB *)map;
  
  //initial record holds size of free list
  bSize_t numEntries = fesb[0].size;
  currentManagedSize = fesb[0].base;

  //init head
  avail = New freeEntry;
  avail->base = fesb[1].base;
  avail->size = fesb[1].size;
  avail->prev = NULL;
  avail->link = NULL;
  prev = avail;

  int i = 1;
  while (i < numEntries) {
    cur = New freeEntry;
    cur->base = fesb[i].base;
    cur->size = fesb[i].size;
    cur->prev = prev;
    prev->link = cur;
    prev = cur;
    i++;
  }
  if (cur) cur->link = NULL;
  
  //now grab handle translation map
  allocatedEntry *e = (allocatedEntry *)(map + sizeof(freeEntrySB)*(numEntries + 1));
  
  //e.base holds the number of allocated handles 
  //e.id holds the maximum number of handles that can be allocated
  //before expanding
  numHandles = e->base;
  maxHandles = e->id;
  sortedByID = New allocatedEntry[maxHandles];
  assert(sortedByID);
  memcpy(&sortedByID[1], &e[1], sizeof(allocatedEntry)*(maxHandles - 1));
  sortedByID[0].base = RAND_MAX;

}

int
compareFunc(const void *_a, const void *_b) {
  allocatedEntry *a = (allocatedEntry *)_a;
  allocatedEntry *b = (allocatedEntry *)_b;
  if (a->base < 0) {
    if (a->base == b->base) return 0;
    else return 1;
  }
  if (b->base < 0) {
    if (a->base == b->base) return 0;
    else return 0;
  }
  if (a->base < b->base) return -1;
  else if (a->base == b->base) return 0;
  else return 1;
}

void
bAllocFF::updateSuperblock() {

  freeEntry *cur = avail;
  freeEntrySB *fesb = (freeEntrySB *)superBlck->freeMap();
  
  int i = 1;
  while (cur != NULL) {
    fesb[i].base = cur->base;
    fesb[i].size = cur->size;
    i++;
    cur=cur->link;
  }
  fesb[0].size = i-1;
  fesb[0].base = currentManagedSize;

  //now do the handles
  allocatedEntry *ae = (allocatedEntry *)(superBlck->freeMap() + 
					  sizeof(freeEntrySB)*i);
  memcpy(&ae[1], &sortedByID[1], sizeof(allocatedEntry)*(maxHandles));
  ae[0].base = numHandles;
  ae[0].id = maxHandles;

  superBlck->flush();
}

blockID_t 
bAllocFF::derefHandle(nodeID_t id) {

  assert(id < maxHandles);
  assert(sortedByID[id].id == id);

  return sortedByID[id].base;
}

bSize_t
bAllocFF::nodeSize(nodeID_t id) {
  assert(id < maxHandles);
  assert(sortedByID[id].id == id);
  return sortedByID[id].size;
}

void
bAllocFF::freeHandle(bOffset_t offset) {
  
  //XXX is 1 always the "lowest" handle?
  int i = 1;
  while ( (i > 0) && (sortedByID[i].base < offset)) i = sortedByID[i].next;
  assert(i < maxHandles);

  sortedByID[i].id = kUnused;
  numHandles--;
  
}

blockID_t 
bAllocFF::makeHandle(blockID_t addr, bSize_t size) {

  assert(addr);

  //check if we have enough master pointers
  if (numHandles == maxHandles - 1) {
    unsigned int len = superBlck->expandFreeMap();
    assert(len > sizeof(allocatedEntry)*maxHandles*2);
    sortedByID = (allocatedEntry *)realloc(sortedByID, sizeof(allocatedEntry)*maxHandles*2);
    assert(sortedByID);
    
    //mark new handles as free
    for (int i = maxHandles; i <= maxHandles*2 ; i++) {
      sortedByID[i].id = kUnused;
      sortedByID[i].base = RAND_MAX;
    }
    maxHandles *= 2;
  }
  
  int id = 1;
  while ((id < maxHandles) && (sortedByID[id].id != kUnused)) id++;
  assert (id < maxHandles);
  sortedByID[id].id = id;
  sortedByID[id].base = addr;
  sortedByID[id].size = size;

  int i = 1;
  while ( (i > 0) && (sortedByID[i].base < addr)) i = sortedByID[i].next;
  sortedByID[id].next = sortedByID[i].next;
  sortedByID[i].next = id;
  
  numHandles++;
  updateSuperblock();
  
  return id;
}

blockID_t
bAllocFF::alloc(bSize_t len) {
  
  freeEntry *Q = avail;
  blockID_t addr;
  do {
    if (Q == NULL) return 0;
    if (Q->size > len) {
      addr = Q->base;
      if (Q->size == len) 
	removeEntry(Q);
      else 
	allocateFromEntry(Q, len);
      blockID_t handle = makeHandle(addr, len);
      updateSuperblock();
      return handle;
    }
    Q = Q->link;
  } while (Q != NULL);
  
  expand();
  return alloc(len);
  
}

//alternate alloc: allocate bytes at given address, don't make handle
blockID_t
bAllocFF::alloc(blockID_t addr, bSize_t len) {

  freeEntry *Q = avail;
  while ( (Q) && (Q->base != addr) ) Q = Q->link;
  assert(Q); assert(Q->size >= len);

  blockID_t ret_addr = Q->base;
  if (Q->size == len) removeEntry(Q);
  else allocateFromEntry(Q, len);
  updateSuperblock();
  
  return ret_addr;
}

void
bAllocFF::removeEntry(freeEntry *Q) {
  if (Q->link) Q->link->prev = Q->prev;
  if (Q->prev) Q->prev->link = Q->link;
  return;
}

void
bAllocFF::addEntry(freeEntry *n, freeEntry *after) {

  assert(after);

  n->link = after->link;
  n->prev = after;
  if (after->link)
    after->link->prev = n;
  after->link = n;
      

}

void
bAllocFF::allocateFromEntry(freeEntry *Q, bSize_t len) {
  assert(Q->size > len);
  Q->size -= len;
  Q->base += len;
  return;
}

void
bAllocFF::dealloc(bOffset_t offset, bSize_t len) {

  freeEntry *Q=avail;
  freeEntry *P=Q->link;

  offset = derefHandle(offset);

  do {
    if ((P == NULL) || (P->base > offset)) { 
      //check upper bound
      if ((P != NULL) && (offset + len == P->base)) {
	P->base -= len;
	P->size += len;
      }
      
      if (Q->base + Q->size == offset) {
	//check for high and low match, coalesce
	if ( (P != NULL) && (P->base == Q->base + Q->size) ) {
	  Q->size += P->size;
	  removeEntry(P);
	  return;
	}
	//just a low match
 	Q->size += len;
	return;
      } else {
	//no adjoining free blocks, add a new free block
	freeEntry *newEntry = new freeEntry;
	newEntry->size = len;
	newEntry->base = offset;
	addEntry(newEntry, Q);
	return;
      }
    }
    Q=P;
    if (P) P=P->link;
  } while (Q != NULL);
  freeHandle(offset);
}

int
bAllocFF::preflightAllocation(bSize_t len) {
  
  freeEntry *Q = avail;
  int lowBase = RAND_MAX;

  do {
    if (Q == NULL) return 0;
    if (Q->size >= len) {
      if (Q->base < lowBase) lowBase = Q->base;
    }
    Q = Q->link;
  } while (Q != NULL);
  
  if (lowBase != RAND_MAX) return lowBase;
  else return 0;
  
}


void
bAllocFF::expand() {
  
  freeEntry *expando = New freeEntry;
  expando->size = currentManagedSize;
  expando->base = currentManagedSize + 1;
  freeEntry *cur = avail;
  while (cur->link) cur = cur->link;
  cur->link = expando;
  expando->link = NULL;
  expando->prev = cur;
  currentManagedSize *= 2;
  updateSuperblock();
}

int
bAllocFF::compactOne(int *handle, blockID_t *newAddr) {

  //find the last allocated block
  int i=1;
  while (sortedByID[i].next > 0) i = sortedByID[i].next; 
  if (i <= 0) return 0;

  blockID_t testAddr = preflightAllocation(sortedByID[i].size);
  if ( (testAddr) && (testAddr < sortedByID[i].base)) {
    *handle = sortedByID[i].id;
    printf("moving %d\n", *handle);
    *newAddr = alloc(testAddr, sortedByID[i].size);
    return 1;
  }
  else return 0;
}

void
bAllocFF::doSwap(int handle, blockID_t newAddr) {
  

  //splice out old handle
  //find prev
  int i = 1;
  while ((i > 0) && (sortedByID[i].next != sortedByID[handle].base)) 
    i = sortedByID[i].next;
  assert(i > 0);
  sortedByID[i].next = sortedByID[handle].next;

  sortedByID[handle].base = newAddr;
  
  //add new one
  i = 1;
  while ((i > 0) && (sortedByID[i].base > newAddr)) i = sortedByID[i].next;
  assert(i > 0);
  sortedByID[handle].next = sortedByID[i].next;
  sortedByID[i].next = handle;
}

bSize_t
bAllocFF::minFileSize() {

  //find the last allocated block
  int i=1;
  while (sortedByID[i].next > 0) i = sortedByID[i].next;
  return sortedByID[i].base + sortedByID[i].size;
}

void
bAllocFF::printRep() {
  freeEntry *curEntry = avail;

  printf("Free Entries:\n");
  while (curEntry) {
    printf("%ld --> %ld: %ld bytes\n", curEntry->base, curEntry->base + curEntry->size, curEntry->size);
    curEntry = curEntry->link;
  }
}
