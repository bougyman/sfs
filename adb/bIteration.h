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
 * bIteration.h
 *
 * The bIteration class is used by the btree->iterate function to
 * return all of the elements of the tree. bIteration objects do not
 * contain internally all of this information, but hold a place holder
 * that the tree uses to return the next element in order 
 */
#ifndef _BITERATION_H_
#define _BITERATION_H_

#include "sysconf.h"
#include <btree_types.h>

class bIteration {

 public:
  bIteration() {lastnode = -1;};
  void setNode(nodeID_t n) { lastnode = n; };
  void setOffset(bLocalSize_t lo) { lastOffset = lo; };
  char null() { return (lastnode == -1); };
  void makeNull() { lastnode = -1; };

  nodeID_t lastNode() { return lastnode; };
  bLocalSize_t off() { return lastOffset; };

 private:
  nodeID_t lastnode;
  bLocalSize_t lastOffset;

};

#endif
