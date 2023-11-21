package main

import (
	"os"
	"sigmaos/authd"
	"sigmaos/rand"
	db "sigmaos/debug"
)

func main() {
	if len(os.Args) != 2 {
		db.DFatalf("Usage :%v kernelId, %d", os.Args[0], len(os.Args))
	}

	var ad *authd.Authd
	ad = &authd.Authd{}
	ad.Sid = rand.String(8)
	ad.KernelId = os.Args[1]	
	
// Internal vs external authsrv
	if(false){
		authmap, err := authd.RunAuthSrv(os.Args[1], "keys/")
		if err != nil {
			db.DFatalf("RunAuthSrv %v err %v\n", os.Args[0], err)
		}

		ad.Auths = authmap
	}else{
		ad.Auths = authd.MkAuthMap()
	}

	if err := authd.RunAuthd(os.Args[1], ad); err != nil {
		db.DFatalf("RunAuthd %v err %v\n", os.Args[0], err)
	}
}
