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
 * btree_static.C -- static methods 
 *
 *
 */

#include <bAllocFF.h>
#include <btree.h>
#include <btree_types.h>
#include <leafNode.h>

#include "stdlib.h"
#include "stdio.h"
#include "string.h"

/*
 * create
 *
 * Create a new, empty database under filename specifying the size of 
 * index and leaf nodes and the factor by which data nodes are larger.
 * simple rule: if values are n times larger than keys, set dataLenFactor
 * to approximately n;
 *
 */
#define FREEMAP_LEN 8192
bError_t
createTree(char * filename, char create, short nodeSize, short dataLenFactor) {

  char *buf;
  struct sb_rep sb;
  int fd_data, fd_tree;
  leafNodeHeader lh;

  //create a file
  char metaName[128];
  strcpy(metaName, filename);
  strcat(metaName, ".data");
  long createFlags = O_WRONLY | O_CREAT;
  if (!create) createFlags |= O_EXCL;

  fd_tree = ::open(filename, createFlags, S_IREAD | S_IWRITE);
  fd_data = ::open(metaName, createFlags, S_IREAD | S_IWRITE);
  if (fd_tree == -1) return bFileCreationError;

  //write the superblock
  bzero(&sb,sizeof(sb));
  sb.magic = 0xDEADBEEF;
  sb.nodeSize = nodeSize;
  sb.freeMapLen = FREEMAP_LEN; //expandable?
  sb.dataLenFactor = dataLenFactor;
  ssize_t err = write(fd_data, &sb, sizeof(sb));
  if (err == -1) return bWriteError;

  lseek(fd_data, 4096, SEEK_SET);
  buf = (char *)malloc(FREEMAP_LEN);
  bzero(buf, FREEMAP_LEN);
  // ALLOC: uncomment below for bAlloc
  //  buf[0] = 3;
  createInitialSuperblock(buf, nodeSize);
  write(fd_data, buf, FREEMAP_LEN);

  lh.nodeType = kLeafTag;
  lh.tag = 1;
  lh.parent = -1;
  lh.dataSize = 0;
  lh.numElems = 0;
  lh.backPtr = 0;
  lh.nextPtr = 0;
  lh.dataIDHint = -1;

  // ALLOC
  //  lseek(fd_tree, lh.tag*sb.nodeSize, SEEK_SET);
  lseek(fd_tree, lh.tag, SEEK_SET);
  char *dummy = new char[sb.nodeSize];
  bzero(dummy, sb.nodeSize);
  memcpy(dummy, &lh, sizeof(lh));
  err = write(fd_tree, dummy, sb.nodeSize);
  if (err != sb.nodeSize) return errno;
  free(dummy);

  close(fd_tree);
  close(fd_data);
  return 0;
}

/*
 * bstrerror - return a string representing the error code err.
 *
 */

char * bstrerror(bError_t err) {

  switch (err) {
  case bFileCreationError:
    return "Error creating disk file";
    break;
  case bOpenError:
    return "Error opening database";
    break;
  case bKeyNotFoundError:
    return "Key not found";
    break;
  case bOutOfMemError:
    return "Out of memory";
    break;
  case bWriteError:
    return "Error writing to disk";
    break;
  case bLongKeyError:
    return "Key too long for node";
    break;
  case bDuplicateKeyError:
    return "Duplicate key";
    break;
  default:
    return strerror(err);
    break;
  }
}

void
startTimer() {
  gettimeofday(&gStartTime, NULL);
}

void
stopTimer() {
  gettimeofday(&gFinishTime, NULL);
}

long
elapsedmsecs() {
  return (gFinishTime.tv_sec - gStartTime.tv_sec)*1000 + (gFinishTime.tv_usec - gStartTime.tv_usec)/1000;
}
