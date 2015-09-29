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
 * superBlock.C 
 *
 * The superblock class is responsible for managing the meta-data associated 
 * with a btree's representation on disk.
 */

#include "superBlock.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "err.h"

#ifndef O_SYNC
# define O_SYNC O_FSYNC
#endif /* !O_SYNC */

#define FREE_MAP_START 4096

// Constructor: reads superblock and freeMap from disk into memory
superBlock::superBlock(char *filename) {
  
  if (filename == NULL)
    filename = strdup("/tmp/btree.dsk");

  //init the 'filesystem' by reading meta data 
  // (using synchronous system calls)
#if defined(__OpenBSD__) || defined (__FreeBSD__)
  fd = open(filename, O_RDWR, 0);
#else
  fd = open(filename, O_RDWR | O_SYNC, 0);
#endif /* defined(__OpenBSD__) || defined (__FreeBSD__) */
  if (fd < 0) fatal("couldn't open disk file");

  //read the superblock into memory (ok if this blocks)
  unsigned long len = read(fd, &sb, sizeof(sb_rep));
  if (len < sizeof(sb_rep)) fatal("short read on superblock?");

  //quick consistency test
  if (sb.magic != MAGIC_NUMBER) fatal("magic numbers don't match\n!");
  
  //allocate free map
  freeMapPtr = (char *)malloc(sb.freeMapLen);
  lseek(fd, FREE_MAP_START, SEEK_SET);
  len = read(fd, freeMapPtr, sb.freeMapLen);
  if (len < 0) fatal("short read on freeMap");

}

//destructor: flush, free memory, close file 
superBlock::~superBlock() {
  
  flush();
  free(freeMapPtr);
  close(fd);
}

//flush: sync the memory representation w/ disk 
int superBlock::flush() {

  lseek(fd, 0, SEEK_SET);
  ssize_t len = write(fd, &sb, sizeof(sb_rep));

  lseek(fd, FREE_MAP_START, SEEK_SET);
  len = write(fd, freeMapPtr, sb.freeMapLen);
  
  if (len < 0) 
    return -1;
  else return 0;
}

//expand free Map: realloc free Map, return new size
bSize_t superBlock::expandFreeMap() {

  sb.freeMapLen *= 2;
  freeMapPtr = (char *)realloc(freeMapPtr, sb.freeMapLen);

  flush();

  return sb.freeMapLen;
}
