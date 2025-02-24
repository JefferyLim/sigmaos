package cachedsvc

import (
	"strconv"
	"sync"

	"sigmaos/proc"
	"sigmaos/serr"
	"sigmaos/sigmaclnt"
	sp "sigmaos/sigmap"
)

//
//  A package to manage a service of cached's
//

const (
	SVRDIR = "servers/"
)

type CachedSvc struct {
	sync.Mutex
	*sigmaclnt.SigmaClnt
	bin     string
	servers []proc.Tpid
	nserver int
	mcpu    proc.Tmcpu
	pn      string
	gc      bool
	public  bool
}

func (cs *CachedSvc) addServer(i int) error {
	// SpawnBurst to spread servers across procds.
	p := proc.MakeProc(cs.bin, []string{cs.pn, strconv.FormatBool(cs.public), SVRDIR + strconv.Itoa(int(i))})
	//	p.AppendEnv("GODEBUG", "gctrace=1")
	if !cs.gc {
		p.AppendEnv("GOGC", "off")
	}
	p.SetMcpu(cs.mcpu)
	_, errs := cs.SpawnBurst([]*proc.Proc{p}, 2)
	if len(errs) > 0 {
		return errs[0]
	}
	if err := cs.WaitStart(p.GetPid()); err != nil {
		return err
	}
	cs.servers = append(cs.servers, p.GetPid())
	return nil
}

func MkCachedSvc(sc *sigmaclnt.SigmaClnt, nsrv int, mcpu proc.Tmcpu, job, bin, pn string, gc, public bool) (*CachedSvc, error) {
	sc.MkDir(pn, 0777)
	if _, err := sc.Create(pn+SVRDIR, 0777|sp.DMDIR, sp.OREAD); err != nil {
		if !serr.IsErrCode(err, serr.TErrExists) {
			return nil, err
		}
	}
	cs := &CachedSvc{
		SigmaClnt: sc,
		bin:       bin,
		servers:   make([]proc.Tpid, 0),
		nserver:   nsrv,
		mcpu:      mcpu,
		pn:        pn,
		gc:        gc,
		public:    public,
	}
	for i := 0; i < cs.nserver; i++ {
		if err := cs.addServer(i); err != nil {
			return nil, err
		}
	}
	return cs, nil
}

func (cs *CachedSvc) AddServer() error {
	cs.Lock()
	defer cs.Unlock()

	n := len(cs.servers)
	return cs.addServer(n)
}

func Server(n string) string {
	return SVRDIR + n
}

func (cs *CachedSvc) Nserver() int {
	return len(cs.servers)
}

func (cs *CachedSvc) SvcDir() string {
	return cs.pn
}

func (cs *CachedSvc) Server(n string) string {
	return cs.pn + Server(n)
}

func (cs *CachedSvc) Stop() error {
	for _, pid := range cs.servers {
		if err := cs.Evict(pid); err != nil {
			return err
		}
		if _, err := cs.WaitExit(pid); err != nil {
			return err
		}
	}
	cs.RmDir(cs.pn + SVRDIR)
	return nil
}
