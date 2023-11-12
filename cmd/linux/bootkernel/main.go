package main

import (
	"os"
	"sigmaos/boot"
	db "sigmaos/debug"
	"sigmaos/kernel"
	sp "sigmaos/sigmap"
	"strings"
)

func main() {
	if len(os.Args) < 8 {
		db.DFatalf("%v: usage kernelid srvs nameds dbip mongoip jaegerip overlays reserveMcpu\n", os.Args[0])
	}
	srvs := strings.Split(os.Args[3], ";")
	param := kernel.Param{
		KernelId: os.Args[1],
		Services: srvs,
		Dbip:     os.Args[4],
		Mongoip:  os.Args[5],
		Jaegerip: os.Args[6],
		Overlays: os.Args[7] == "true",
	}
	if len(os.Args) >= 9 {
		param.ReserveMcpu = os.Args[8]
	}
	db.DPrintf(db.KERNEL, "param %v\n", param)
	h := sp.SIGMAHOME
	p := os.Getenv("PATH")
	os.Setenv("PATH", p+":"+h+"/bin/kernel:"+h+"/bin/linux:"+h+"/bin/user")
	addrs, err := sp.String2Taddrs(os.Args[2])
	if err != nil {
		db.DFatalf("%v: String2Taddrs %v\n", os.Args[0], err)
	}
	if err := boot.BootUp(&param, addrs); err != nil {
		db.DFatalf("%v: boot %v err %v\n", os.Args[0], os.Args[1:], err)
	}
	os.Exit(0)
}
