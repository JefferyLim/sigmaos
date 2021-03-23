package locald

import (
	//	"github.com/sasha-s/go-deadlock"
	"log"
	"net"
	"sync"
	"time"

	db "ulambda/debug"
	"ulambda/fsclnt"
	"ulambda/fslib"
	np "ulambda/ninep"
	npo "ulambda/npobjsrv"
	"ulambda/npsrv"
)

type LocalD struct {
	//	mu deadlock.Mutex
	mu   sync.Mutex
	cond *sync.Cond
	load int // XXX bogus
	bin  string
	nid  uint64
	root *Obj
	done bool
	ip   string
	ls   map[string]*Lambda
	srv  *npsrv.NpServer
	*fslib.FsLib
	group sync.WaitGroup
}

func MakeLocalD(bin string) *LocalD {
	ld := &LocalD{}
	ld.cond = sync.NewCond(&ld.mu)
	ld.load = 0
	ld.nid = 0
	ld.bin = bin
	db.Name("locald")
	ld.root = ld.MakeObj([]string{}, np.DMDIR, nil).(*Obj)
	ld.root.time = time.Now().Unix()
	ld.ls = map[string]*Lambda{}
	ip, err := fsclnt.LocalIP()
	ld.ip = ip
	if err != nil {
		log.Fatalf("LocalIP %v %v\n", fslib.SCHED, err)
	}
	ld.srv = npsrv.MakeNpServer(ld, ld.ip+":0")
	fsl := fslib.MakeFsLib("locald")
	fsl.Mkdir(fslib.LOCALD_ROOT, 0777)
	ld.FsLib = fsl
	err = fsl.PostServiceUnion(ld.srv.MyAddr(), fslib.LOCALD_ROOT, ld.srv.MyAddr())
	if err != nil {
		log.Fatalf("PostServiceUnion failed %v %v\n", ld.srv.MyAddr(), err)
	}
	return ld
}

func (ld *LocalD) spawn(a []byte) (*Lambda, error) {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	l := &Lambda{}
	l.ld = ld
	err := l.init(a)
	if err != nil {
		return nil, err
	}
	ld.ls[l.Pid] = l
	return l, nil
}

func (ld *LocalD) Connect(conn net.Conn) npsrv.NpAPI {
	return npo.MakeNpConn(ld, conn)
}

func (ld *LocalD) Done() {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	ld.done = true
}

func (ld *LocalD) readDone() bool {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	return ld.done
}

func (ld *LocalD) Root() npo.NpObj {
	return ld.root
}

func (ld *LocalD) Resolver() npo.Resolver {
	return nil
}

// Worker runs one lambda at a time
func (ld *LocalD) Worker() {
	// XXX pin to a core
	for !ld.readDone() {
		db.DLPrintf("LOCALD", "Getting lambda\n")
		b, err := ld.GetLambda()
		db.DLPrintf("LOCALD", "Got lambda %v\n", b)
		if err != nil && err.Error() == "EOF" {
			//			db.DLPrintf("LOCALD", "EOF on GetLambda %v\n", b)
			log.Printf("EOF on GetLambda %v\n", b)
			continue
		}
		if err != nil {
			log.Fatalf("Locald GetLambda error %v, %v\n", err, b)
		}
		// XXX return err from spawn
		l, err := ld.spawn(b)
		if err != nil {
			log.Fatalf("Locald spawn error %v\n", err)
		}
		l.run()
	}
	log.Printf("LOCALD WORKER DONE\n")
	ld.group.Done()
}

func (ld *LocalD) Work() {
	for i := uint(0); i < NCores; i++ {
		ld.group.Add(1)
		go ld.Worker()
	}
	ld.group.Wait()

}
