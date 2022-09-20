package main

import (
	"os"

	db "sigmaos/debug"
	"sigmaos/machine"
)

func main() {
	if len(os.Args) != 1 {
		db.DFatalf("Usage: %v", os.Args[0])
	}
	m := machine.MakeMachined(os.Args[1:])
	m.Work()
}
