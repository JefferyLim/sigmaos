package main

import (
	"log"
	"os"

	db "ulambda/debug"
	"ulambda/fsclnt"
	"ulambda/fslibsrv"
	"ulambda/linuxsched"
	"ulambda/memfsd"
	"ulambda/procinit"
	"ulambda/seccomp"
)

func main() {
	linuxsched.ScanTopology()
	// started as a ulambda
	name := memfsd.MEMFS + "/" + os.Args[1]
	ip, err := fsclnt.LocalIP()
	if err != nil {
		log.Fatalf("%v: no IP %v\n", os.Args[0], err)
	}
	db.Name(name)
	fsd := memfsd.MakeFsd(ip + ":0")
	fsl, err := fslibsrv.InitFs(name, fsd, nil)
	if err != nil {
		log.Fatalf("%v: InitFs failed %v\n", os.Args[0], err)
	}
	sclnt := procinit.MakeProcClnt(fsl.FsLib, procinit.GetProcLayersMap())
	sclnt.Started(os.Args[1])
	seccomp.LoadFilter()
	fsd.Serve()
	sclnt.Exited(os.Args[1], "OK")
	fsl.ExitFs(name)
}
