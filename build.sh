#!/bin/bash

usage() {
  echo "Usage: $0 [--target target ] [--parallel]" 1>&2
}

PARALLEL=""
TARGET="local"
while [[ "$#" -gt 0 ]]; do
  case "$1" in
  --parallel)
    shift
    PARALLEL="--parallel"
    ;;
  --target)
    shift
    TARGET="$1"
    shift
    ;;
  -help)
    usage
    exit 0
    ;;
  *)
   echo "unexpected argument $1"
   usage
   exit 1
  esac
done

if [ $# -gt 0 ]; then
    usage
    exit 1
fi

TMP=/tmp/sigmaos

# tests uses hosts /tmp, which mounted in kernel container.
mkdir -p $TMP

# build and start db container
if [ "${TARGET}" != "aws" ]; then
   ./start-db.sh
fi

# XXX this will do go somewhere else
if ! docker node ls | grep -q 'Leader'; then
    docker swarm init
fi 

# XXX move and one per realm
if ! docker network ls | grep -q 'sigmanet'; then
    docker network create --driver overlay sigmanet --attachable
fi
   

# build binaries for host
./make.sh --norace $PARALLEL linux

# build containers
DOCKER_BUILDKIT=1 docker build --build-arg target=$TARGET --build-arg parallel=$PARALLEL -t arielszekely/sigmabase .
docker push arielszekely/sigmabase
docker build -f Dockerkernel -t arielszekely/sigmaos .
docker push arielszekely/sigmaos
docker build -f Dockeruser -t arielszekely/sigmauser .
docker push arielszekely/sigmauser
