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
 * replacement.h - definitions for class replacementQ which (along with a hash table)
 *                 in nodeBuf supports LRU replacement. Use add to add a new item to the
 *                 replacement Q, touch when an exisiting item is modified, and purgeOne
 *		   to produce the next item to be released (also removes the item from
 *		   the queue.
 */

#ifndef _REPLACEMENT_H_
#define _REPLACEMENT_H_

struct replacementRec;
class replacementQ;

#include <btree_types.h>

struct replacementRec {
  nodeID_t ID;
  replacementRec *next;
  replacementRec *prev;
  replacementRec(nodeID_t id) { ID = id;};
};

class replacementQ {
 public:
  nodeID_t purgeOne();
  nodeID_t next();
  replacementRec *add(nodeID_t);
  void touch(replacementRec *rec);
  replacementRec *remove(nodeID_t i);
  char inQueue(nodeID_t n);
  replacementQ();
  void printRep(char *msg);

 private:
  replacementRec *head;
  replacementRec *tail;

};

#endif
