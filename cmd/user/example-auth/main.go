package main

import (
	"os"
	"strconv"
	dbg "sigmaos/debug"
	auth "sigmaos/auth_server"
)

func main() {
	if len(os.Args) != 2 {
		dbg.DFatalf("Usage: %v public", os.Args[0])
		return
	}
	public, err := strconv.ParseBool(os.Args[1])
	if err != nil {
		dbg.DFatalf("ParseBool %v err %v\n", os.Args[0], err)
	}
	if err := auth.RunAuthSrv(public); err != nil {
		dbg.DFatalf("RunAuthSrv %v err %v\n", os.Args[0], err)
	}
}
