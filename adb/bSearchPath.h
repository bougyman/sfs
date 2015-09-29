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
 * bSearchPath.h
 *
 * A LIFO stack used to track the path of a search through the tree. 
 */

#ifndef _BSEARCHPATH_H_
#define _BSEARCHPATH_H_

#include "btree_types.h"

#define MAXHEIGHT 64

class bSearchPath {

 public:
  bSearchPath();
  
  void addNode(nodeID_t node);
  nodeID_t pop();
  nodeID_t lastNode();

 private:
  nodeID_t stack[MAXHEIGHT];
  int SP;

};

#endif







