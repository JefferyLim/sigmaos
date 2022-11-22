package main

import (
	"os"

	db "sigmaos/debug"
	"sigmaos/hotel"
)

func main() {
	if len(os.Args) != 2 {
		db.DFatalf("Usage: %v jobname", os.Args[0])
	}
	if err := hotel.RunSearchSrv(os.Args[0]); err != nil {
		db.DFatalf("Start %v err %v\n", os.Args[0], err)
	}
}
