#!/bin/sh

CACHEFILE=$HOME/.sfs/srpcache

if [ ! -f $CACHEFILE ]; then
  exit 0
fi

if [ $# -eq 0 ]; then
  cat $CACHEFILE
elif [ $# -eq 1 ]; then
  echo $1 >> $CACHEFILE
else
  exit 0
fi
