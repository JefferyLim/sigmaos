package named

import (
	"fmt"
	"path"
	"strconv"
	"sync"
	"time"

	"sigmaos/container"
	"sigmaos/crash"
	db "sigmaos/debug"
	"sigmaos/fsetcd"
	"sigmaos/fslibsrv"
	"sigmaos/leaderetcd"
	"sigmaos/port"
	"sigmaos/portclnt"
	"sigmaos/proc"
	"sigmaos/semclnt"
	"sigmaos/sigmaclnt"
	sp "sigmaos/sigmap"
	"sigmaos/sigmasrv"
)

type Named struct {
	*sigmaclnt.SigmaClnt
	*sigmasrv.SigmaSrv
	mu    sync.Mutex
	fs    *fsetcd.FsEtcd
	elect *leaderetcd.Election
	job   string
	realm sp.Trealm
	crash int
	sess  *fsetcd.Session
}

func Run(args []string) error {
	db.DPrintf(db.NAMED, "%v: args %v net %q\n", proc.GetPid(), args, proc.GetNet())
	if len(args) != 3 {
		return fmt.Errorf("%v: wrong number of arguments %v", args[0], args)
	}
	nd := &Named{}
	nd.realm = sp.Trealm(args[1])
	crashing, err := strconv.Atoi(args[2])
	if err != nil {
		return fmt.Errorf("%v: crash %v isn't int", args[0], args[2])
	}
	nd.crash = crashing

	uname := sp.Tuname(proc.GetPid().String())
	sc, err := sigmaclnt.MkSigmaClnt(uname)
	if err != nil {
		return err
	}
	nd.SigmaClnt = sc
	db.DPrintf(db.JEFF, "hello world %v", sc.Uuid())

	pn := path.Join(sp.REALMS, nd.realm.String()) + ".sem"
	sem := semclnt.MakeSemClnt(nd.FsLib, pn)
	if nd.realm != sp.ROOTREALM {
		// create semaphore to signal realmd when we are the leader
		// and ready to serve requests.  realmd downs this semaphore.
		li, err := sc.LeaseClnt.AskLease(pn, fsetcd.LeaseTTL)
		if err != nil {
			return err
		}
		li.KeepExtending()
		if err := sem.InitLease(0777, li.Lease()); err != nil {
			return err
		}
	}

	nd.Started()
	ch := make(chan struct{})
	go nd.waitExit(ch)

	db.DPrintf(db.NAMED, "started %v %v %v\n", proc.GetPid(), nd.realm, proc.GetRealm())

	if err := nd.startLeader(); err != nil {
		db.DPrintf(db.NAMED, "%v: startLeader %v err %v\n", proc.GetPid(), nd.realm, err)
		return err
	}
	defer nd.fs.Close()

	mnt, err := nd.mkSrv()
	if err != nil {
		db.DFatalf("Error mkSrv %v\n", err)
	}

	pn = sp.NAMED
	if nd.realm == sp.ROOTREALM {
		db.DPrintf(db.ALWAYS, "SetRootNamed %v mnt %v\n", nd.realm, mnt)
		if err := nd.fs.SetRootNamed(mnt); err != nil {
			db.DFatalf("SetNamed: %v", err)
		}
	} else {
		// note: the named proc runs in rootrealm; maybe change it XXX
		pn = path.Join(sp.REALMS, nd.realm.String())
		db.DPrintf(db.ALWAYS, "MkMountSymlink %v %v lid %v\n", nd.realm, pn, nd.sess.Lease())
		if err := nd.MkMountSymlink(pn, mnt, nd.sess.Lease()); err != nil {
			db.DPrintf(db.NAMED, "mount %v at %v err %v\n", nd.realm, pn, err)
			return err
		}

		// Signal realmd we are ready
		if err := sem.Up(); err != nil {
			db.DPrintf(db.NAMED, "%v sem up %v err %v\n", nd.realm, sem.String(), err)
			return err
		}
	}

	nd.getRoot(pn + "/")

	if err := nd.CreateLeaderFile(path.Join(sp.NAME, nd.elect.Key()), nil, sp.TleaseId(nd.sess.Lease()), nd.elect.Fence()); err != nil {
		db.DPrintf(db.NAMED, "CreateElectionInfo %v err %v\n", nd.elect.Key(), err)
	}

	if nd.crash > 0 {
		crash.Crasher(nd.SigmaClnt.FsLib)
	}

	<-ch

	db.DPrintf(db.NAMED, "%v: named done %v %v\n", proc.GetPid(), nd.realm, mnt)

	if err := nd.resign(); err != nil {
		db.DPrintf(db.NAMED, "resign %v err %v\n", proc.GetPid(), err)
	}

	nd.SigmaSrv.SrvExit(proc.MakeStatus(proc.StatusEvicted))

	return nil
}

func (nd *Named) mkSrv() (sp.Tmount, error) {
	ip, err := container.LocalIP()
	if err != nil {
		return sp.NullMount(), err
	}
	root := rootDir(nd.fs, nd.realm)
	var pi portclnt.PortInfo
	if nd.realm == sp.ROOTREALM || proc.GetNet() == sp.ROOTREALM.String() {
		ip = ip + ":0"
	} else {
		_, pi0, err := portclnt.MkPortClntPort(nd.SigmaClnt.FsLib)
		if err != nil {
			return sp.NullMount(), err
		}
		pi = pi0
		ip = ":" + pi.Pb.RealmPort.String()
	}

	uname := sp.Tuname(proc.GetPid().String())
	srv := fslibsrv.BootSrv(root, ip, nd.attach, nd.detach, nil, uname)
	if srv == nil {
		return sp.NullMount(), fmt.Errorf("BootSrv err %v\n", err)
	}

	ssrv := sigmasrv.MakeSigmaSrvSess(srv, sp.Tuname(proc.GetPid().String()), nd.SigmaClnt, "")
	if err := ssrv.MountRPCSrv(newLeaseSrv(nd.fs)); err != nil {
		return sp.NullMount(), err
	}
	nd.SigmaSrv = ssrv

	mnt := sp.MkMountServer(nd.MyAddr())
	if nd.realm != sp.ROOTREALM {
		mnt = port.MkPublicMount(pi.Hip, pi.Pb, proc.GetNet(), nd.MyAddr())
	}

	db.DPrintf(db.NAMED, "mkSrv %v %v %v %v %v\n", nd.realm, ip, srv.MyAddr(), nd.elect.Key(), mnt)

	return mnt, nil
}

func (nd *Named) attach(cid sp.TclntId) {
	db.DPrintf(db.NAMED, "named: attach %v\n", cid)
	// nd.fs.Recover(cid)
}

func (nd *Named) detach(cid sp.TclntId) {
	db.DPrintf(db.NAMED, "named: detach %v\n", cid)
	// nd.fs.Detach(cid)
}

func (nd *Named) resign() error {
	if err := nd.SessSrv.StopServing(); err != nil {
		return err
	}
	return nd.elect.Resign()
}

func (nd *Named) getRoot(pn string) error {
	sts, err := nd.GetDir(pn)
	if err != nil {
		db.DPrintf(db.NAMED, "getdir %v err %v\n", pn, err)
		return err
	}
	db.DPrintf(db.NAMED, "getdir %v sts %v\n", pn, sp.Names(sts))
	return nil
}

func (nd *Named) waitExit(ch chan struct{}) {
	for {
		err := nd.WaitEvict(proc.GetPid())
		if err != nil {
			db.DPrintf(db.NAMED, "Error WaitEvict: %v", err)
			time.Sleep(time.Second)
			continue
		}
		db.DPrintf(db.NAMED, "candidate %v %v evicted\n", nd.realm, proc.GetPid().String())
		ch <- struct{}{}
	}
}
