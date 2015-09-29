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
 * replacement.h - implementation of class replacementQ which (along with a hash table)
 *                 in nodeBuf supports LRU replacement.
 */

#include <replacement.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef DMALLOC
#include "dmalloc.h"
#endif

replacementQ::replacementQ() {

  head = tail = NULL;
}

/*
 * add - add a New entry for node id and place it at the front of the list. Return
 *       a pointer to the New entry
 */
replacementRec * replacementQ::add(nodeID_t id) {

  //printRep("add");

  replacementRec *r = (replacementRec *)malloc(sizeof(replacementRec));
  r->ID = id;

  replacementRec *t = head;
  while ((t) && (t->ID != id)) t = t->next;
  if (t != NULL)  {
    printf("added duplicate id %ld to q", id);
    return NULL;
  }

  if (head == NULL) {
    head = r;
    tail = r;
    r->next = NULL;
    r->prev = NULL;
  } else {
    r->next = head;
    head = r;
    r->prev = NULL;
    r->next->prev = r;
  }

  //printRep("~add");
  return r;
}

/*
 * remove - remove the entry corresponding to nodeID from the queue
 */
replacementRec *
replacementQ::remove(nodeID_t id) {

  //  printRep("remove");

  if (head == NULL) return NULL;
  
  replacementRec *r = head;
  while ((r) && (r->ID != id)) r = r->next;
  if (r == NULL) return NULL;

  if (r == head) {
    head = r->next;
    if (r->next) r->next->prev = NULL;
    return r;
  }

  if (r == tail) {
    tail = r->prev;
    if (tail) tail->next = NULL;
    return r;
  }

  if (r->prev) 
    r->prev->next = r->next;
  
  if (r->next)
    r->next->prev = r->prev;

  //printRep("~remove");
  return r;
}

/*
 * purgeOne - return the id of the least recently used node and remove it from the Q
 */
nodeID_t replacementQ::purgeOne() {

  if (head == NULL) {
    //empty list, return an error condition
    return 0;
  }

  //delete from the tail
  replacementRec *victim = tail;
  if (tail->prev) {
    tail = tail->prev;
    tail->next = NULL;
  }
  else 
    head = tail = NULL; //last element
  
  nodeID_t retval = victim->ID;
  free(victim);

  return retval;
}

nodeID_t replacementQ::next() {

  if (head == NULL) return -1;
  else return tail->ID;
}

char 
replacementQ::inQueue(nodeID_t n) {

  replacementRec *r = head;
  while (r) {
    if (r->ID == n) return 1;
    r = r->next;
  }

  return 0;
}

/*
 * touch - move rec to the head of the list
 */
void replacementQ::touch(replacementRec *rec) {

  //printRep("touch");

  if (head == NULL) return;

  if (head->ID == rec->ID) return;

  remove(rec->ID);

  //insert it in the front
  if (head == NULL) {
    head = rec;
    tail = rec;
    rec->next = NULL;
    rec->prev = NULL;
  } else {
    rec->next = head;
    head = rec;
    rec->prev = NULL;
    rec->next->prev = rec;
  }

  //printRep("~touch");
}
  
void 
replacementQ::printRep(char *msg) {

  replacementRec *r = head;

  printf("%s : ", msg);
  while (r) {

    printf("%ld ", r->ID);
    r = r->next;
  }
  printf("\n");
}
