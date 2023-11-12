package main

import (
	"os"

	auth "sigmaos/authsrv"
	db "sigmaos/debug"
)

func main() {
	if len(os.Args) != 2 {
		db.DFatalf("Usage :%v kernelId, %d", os.Args[0], len(os.Args))
	}

	if err := auth.RunAuthSrv(os.Args[1]); err != nil {
		db.DFatalf("RunAuthSrv %v err %v\n", os.Args[0], err)
	}
}
