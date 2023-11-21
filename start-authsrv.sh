#!/bin/bash

#
# Start the authsrv
#

usage() {
    echo "Usage : $0 --keys <key dir>" 1>&2
}

./bin/linux/authsrv $1 &

