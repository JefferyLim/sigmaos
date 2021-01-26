#!/bin/sh

./bin/named &
./bin/proxyd &
sudo mount -t 9p -o tcp,name=`whoami`,uname=`whoami`,port=1110 127.0.0.1 /mnt/9p
./bin/schedd &

# make fake file system
mkdir -p /mnt/9p/fs
mkdir -p /mnt/9p/kv
mkdir -p /mnt/9p/gg

#cp ~/classes/6824-2021/6.824-golabs-staff/mygo/src/main/pg-*.txt /mnt/9p/fs

