#!/bin/bash

export NAMED=:1111

go clean -testcache

#
# test some support package
#

go test $1 ulambda/linuxsched
go test $1 ulambda/perf

#
# tests without servers
#
go test $1 ulambda/ninep
go test $1 ulambda/memfs
go test $1 ulambda/pathclnt

#
# test with just named
#
go test $1 ulambda/reader
go test $1 ulambda/writer
go test $1 ulambda/stats
go test $1 ulambda/fslib
go test $1 ulambda/leaderclnt
go test $1 ulambda/semclnt

#
# test proxy
#

# ./proxy/test.sh

#
# tests kernel (without realms)
#

go test $1 ulambda/procclnt
go test $1 ulambda/ux
# go test -v ulambda/fslib -path "name/ux/~ip/fslibtest/" -run InitFs
go test $1 ulambda/s3
go test $1 ulambda/kernel
go test $1 ulambda/epochclnt
go test $1 ulambda/leadertest
go test $1 ulambda/snapshot

go test $1 ulambda/group

# dbd_test and wwwd_test requires mariadb running
pgrep mariadb >/dev/null && go test $1 ulambda/dbd
pgrep mariadb >/dev/null && go test $1 ulambda/cmd/user/wwwd


go test $1 ulambda/mr
go test $1 ulambda/kv

# XXX broken
# go test $1 ulambda/cmd/user/test2pc
# go test $1 ulambda/cmd/user/test2pc2

#
# test with realms
#

go test $1 ulambda/realm

# run without realm?
# XXX needs fixing
# go test $1 -timeout=45m ulambda/replica
 
