package replica

import (
//	db "sigmaos/debug"
//	"sigmaos/fslib"
//	"sigmaos/protclnt"
//	"sigmaos/replchain"
)

//func GetChainReplConfig(name, port, configPath, addr, unionDirPath, symlinkPath string) *replchain.ChainReplConfig {
//	fsl := fslib.MakeFsLib(name + "-replica:" + port)
//	clnt := protclnt.MakeClnt()
//	config, err := replchain.ReadReplConfig(configPath, addr, fsl, clnt)
//	// Reread until successful
//	for err != nil {
//		db.DPrintf("RSRV", "Couldn't read repl config: %v\n", err)
//		config, err = replchain.ReadReplConfig(configPath, addr, fsl, clnt)
//	}
//	config.UnionDirPath = unionDirPath
//	config.SymlinkPath = symlinkPath
//	return config
//}
