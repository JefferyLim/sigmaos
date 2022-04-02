package main

import (
	"os"
	"time"

	db "ulambda/debug"
	"ulambda/fslib"
	np "ulambda/ninep"
	"ulambda/proc"
	"ulambda/procclnt"
)

//
// Crashing proc
//

func main() {
	fsl := fslib.MakeFsLib(os.Args[0] + "-" + proc.GetPid().String())
	pclnt := procclnt.MakeProcClnt(fsl)
	err := pclnt.Started()
	if err != nil {
		db.DFatalf("Started: error %v\n", err)
	}
	if error := fsl.Disconnect(np.NAMED); error != nil {
		db.DFatalf("Disconnect %v name fails err %v\n", os.Args, error)
	}

	time.Sleep(100 * time.Millisecond)

	pclnt.Exited(proc.MakeStatus(proc.StatusOK))
}
