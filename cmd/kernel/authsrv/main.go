package main

import (
    "os"

     db "sigmaos/debug"
     auth "sigmaos/authsrv"
)


func main() {
    if err := auth.RunAuthSrv(false); err != nil {
		db.DFatalf("RunAuthSrv %v err %v\n", os.Args[0], err)
	}
}
