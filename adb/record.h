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
 * record.h 
 *
 * class record is a wrapper class which holds a variable length
 * key/value pair.
 */

#ifndef _RECORD_H_
#define _RECORD_H_

#include <btree_types.h>

class record {

 public:
  record(void *key, int keyLen, void *value, int valueLen);
  record::record(record *rec);
  ~record();
  void dealloc();
  void *getKey(bSize_t *len);
  void *getValue(bSize_t *len);

  void setKey(void *key, bSize_t len);
  void setValue(void *value, bSize_t len);
  bSize_t recordLen() { return keyLen + valueLen;};

 private:
  void *key;
  void *value;
  bSize_t keyLen;
  bSize_t valueLen;
};

record * recordDup(record *in);


#endif

