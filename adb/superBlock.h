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
 * superBlock.h 
 *
 * The superblock class is responsible for managing the meta-data associated 
 * with a btree's representation on disk. The data is held in a file distinct 
 * from that containing the tree data and is managed by synchronous I/O
 */

#ifndef _SUPER_BLOCK_H_
#define _SUPER_BLOCK_H_

#include "btree_types.h"

#define MAGIC_NUMBER 0xDEADBEEF

struct sb_rep {
  unsigned long magic;
  bSize_t size; //of tree in blocks
  bSize_t dataLenFactor; //how much larger are data blocks
  unsigned long freeMapLen;
  bLocalSize_t nodeSize;
  //pad it out to 4K
  char padding[4074];
};

class superBlock {

 private:
  sb_rep sb;
  char *freeMapPtr;
  int fd;

 public:
  superBlock(char *filename);
  ~superBlock();

  int flush();
  
  bSize_t treeSize() { return sb.size; };
  bSize_t dataLenFactor() { return sb.dataLenFactor; };
  bLocalSize_t nodeSize() { return sb.nodeSize; };
  char *freeMap() { return freeMapPtr; };
  bSize_t freeMapSize() { return sb.freeMapLen; };
  bSize_t expandFreeMap();

};


#endif
