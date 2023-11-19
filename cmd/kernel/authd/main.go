package main

import (
	"os"

	"sigmaos/authd"
	db "sigmaos/debug"
)

func main() {
	if len(os.Args) != 2 {
		db.DFatalf("Usage :%v kernelId, %d", os.Args[0], len(os.Args))
	}

    authsrv, err := authd.RunAuthSrv(os.Args[1])
	if err != nil {
		db.DFatalf("RunAuthSrv %v err %v\n", os.Args[0], err)
	}

	if err := authd.RunAuthd(os.Args[1], authsrv); err != nil {
		db.DFatalf("RunAuthd %v err %v\n", os.Args[0], err)
	}
}
