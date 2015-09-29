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
 * record.C
 *
 * class record is a wrapper class which holds a variable length
 * key/value pair.
 */


#include <record.h>
#include <stdlib.h>
#include <string.h>

record::record(void *Key, int KeyLen, void *Value, int ValueLen) {

  key = Key;
  value = Value;
  keyLen = KeyLen;
  valueLen = ValueLen;
}

//copy constructor (unlike above, this one allocates new data)
record::record(record *rec) {
  bSize_t nkeyLen;
  void *nkey = rec->getKey(&nkeyLen);
  bSize_t nvalueLen;
  void *nvalue = rec->getValue(&nvalueLen);
  
  key = new char[nkeyLen];
  value = new char[nvalueLen];
  memcpy(key, nkey, nkeyLen);
  memcpy(value, nvalue, nvalueLen);
  keyLen = nkeyLen;
  valueLen = nvalueLen;

}
record::~record() {
}

void
record::dealloc() {

  ::free(key);
  ::free(value);
  
}

record *
recordDup(record *in) {
  bSize_t keyLen, valueLen;
  void *key = in->getKey(&keyLen);
  void *value = in->getValue(&valueLen);

  char * newKey = new char[keyLen];
  char * newValue = new char[valueLen];
  memcpy(newKey, key, keyLen);
  memcpy(newValue, value, valueLen);
  return new record (newKey, keyLen, newValue, valueLen);

}
void *
record::getKey(bSize_t *len) {

  *len = keyLen;
  return key;
}

void *
record::getValue(bSize_t *len) {
  *len = valueLen;
  return value;
}

void
record::setKey(void *Key, bSize_t len) {
  key = Key;
  keyLen = len;
}

void
record::setValue(void *Value, bSize_t len) {
  value = Value;
  valueLen = len;
}
