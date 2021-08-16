#!/bin/bash

export NAMED=127.0.0.1:1111

go test $1 ulambda/ninep
go test $1 ulambda/memfs
go test $1 ulambda/fsclnt
go test $1 ulambda/fslib_test
go test $1 ulambda/sync
(cd nps3; go test $1)
go test $1 ulambda/procd
go test $1 ulambda/jobsched
(cd kv; go test $1)
./test-mr.sh
./test-kv.sh
(cd replica; go test -timeout=45m $1)
