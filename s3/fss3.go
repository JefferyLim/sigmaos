package fss3

import (
	//"context"
	"sync"

	//"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	gopath "path"
	"sigmaos/container"
	db "sigmaos/debug"
	"sigmaos/fslib"
	"sigmaos/path"
	"sigmaos/perf"
	"sigmaos/rpcclnt"
	sp "sigmaos/sigmap"
	"sigmaos/sigmasrv"
)

var fss3 *Fss3

type Fss3 struct {
	*sigmasrv.SigmaSrv

	mu     sync.Mutex
	rpcc   *rpcclnt.RPCClnt
	client map[sp.Tuuid]*s3.Client
}

func RunFss3(buckets []string) {

	db.DPrintf(db.JEFF, "buckets? %v", buckets)
	ip, err := container.LocalIP()
	if err != nil {
		db.DFatalf("LocalIP %v %v\n", sp.UX, err)
	}
	fss3 = &Fss3{}
	root := makeDir("", path.Path{}, sp.DMDIR)
	ssrv, err := sigmasrv.MakeSigmaSrvRoot(root, ip+":0", sp.S3, sp.S3REL)
	if err != nil {
		db.DFatalf("Error MakeSigmaSrv: %v", err)
	}
	p, err := perf.MakePerf(perf.S3)
	if err != nil {
		db.DFatalf("Error MakePerf: %v", err)
	}
	defer p.Done()

	fss3.SigmaSrv = ssrv

	fss3.client = make(map[sp.Tuuid]*s3.Client)

	fn := gopath.Join(sp.AUTHD, "jeff")
	sc := ssrv.SigmaClnt()
	rpcc, err := rpcclnt.MkRPCClnt([]*fslib.FsLib{sc.FsLib}, fn)
	if err != nil {
		db.DFatalf("Error MkRPCCLnt: %v", err)
	}

	fss3.rpcc = rpcc
	ssrv.RunServer()
}
