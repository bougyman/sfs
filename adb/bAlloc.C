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
#include "bAlloc.h"
#include "btree.h"

bAlloc::bAlloc(superBlock *sb) {

  for (int i = 0; i < 8; i++) 
    masks[i] = 1 << i;
  
  map = sb->freeMap();
  size = mapLen = sb->freeMapSize() * 8;
  blocksFree = mapLen;

  superBlck = sb;
}

blockID_t
bAlloc::alloc(bSize_t len) {

  //  char iteration = 0;
  long curBlock=0, runStart, runLen = 0;
  
  if (blocksFree < len) expand();

  //  curBlock = runStart = cursor;
  //do {
  do {
      
    while (!blockFree(curBlock) && (curBlock < mapLen)) curBlock++;
    if (curBlock == mapLen) goto fail;
    runStart = curBlock;
    
    while ((runLen < len) && (blockFree(curBlock++)) && (curBlock < mapLen)) runLen++;
    if (curBlock == mapLen) goto fail;

    if (runLen == len) {
      for (int i = runStart; i < runStart + runLen; i++) 
	markUsed(i);
      cursor += runLen;
      blocksFree -= len;
      return runStart;
    }
    
    runLen = 0;
  } while (curBlock < mapLen);
    
  //    cursor = curBlock = 0;
  // iteration++;
  //} while (iteration < 2);

  //if we get here we failed, expand and try again
 fail:
  expand();
  return alloc(len);
}

void
bAlloc::markFree(blockID_t b) {
  map[b / 8] &= ~masks[b % 8];
}


char
bAlloc::blockFree(blockID_t b) {

  return !(map[b / 8] & masks[b % 8]);
}

void
bAlloc::markUsed(blockID_t b) {
  map[b / 8] |= masks[b % 8]; 
}
  
void
bAlloc::dealloc(bOffset_t offset, bSize_t len) {

  for (int i = offset; i < offset + len; i++) markFree(i);
}

int
bAlloc::preflightAllocation(bSize_t len) {

  char iteration = 0;
  long curBlock, runStart, runLen = 0;
  
  if (blocksFree < len) expand();

  curBlock = runStart = 0;
  do {
    do {
      while (!blockFree(curBlock)) curBlock++;
      runStart = curBlock;
      while ((runLen < len) && (blockFree(curBlock++))) runLen++;
      if (runLen == len) { 
	return 1;
	//next call will presumably be the real alloc
	cursor = runStart;
      }
      runLen = 0;
    } while (curBlock < size);
    
    curBlock = 0;
    iteration++;
  } while (iteration < 2);

  expand();
  return preflightAllocation(len);
}

void
bAlloc::expand() {
  
  //expand the freeMap to fit
  long oldMapLen = mapLen;
  size = mapLen = superBlck->expandFreeMap() * 8;
  blocksFree += (mapLen - oldMapLen);
  map = superBlck->freeMap();
  cursor = 0;
}











