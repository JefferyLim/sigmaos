#!/bin/bash

#
# Run from directory thas has "bin"
#

N=":1111"
if [ $# -eq 1 ]
then
    N=$1
fi

if [[ -z "${NAMED}" ]]; then
  export NAMED=$N
fi

#./bin/kernel/boot
./bin/realm/realmmgr . &
sleep 2
./bin/realm/realmd . &
sleep 1
./bin/realm/create 1000

./mount.sh
mkdir -p /mnt/9p/fs   # make fake file system
mkdir -p /mnt/9p/kv
mkdir -p /mnt/9p/gg
mkdir -p /mnt/9p/memfsd
