package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/thanhpk/randstr"

	db "sigmaos/debug"
	"sigmaos/fslib"
	np "sigmaos/ninep"
	"sigmaos/proc"
	"sigmaos/procclnt"
	"sigmaos/twopc"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %v index opcode delay_len\n", os.Args[0])
		os.Exit(1)
	}
	p, err := MkTest2Participant2(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v: error %v", os.Args[0], err)
		os.Exit(1)
	}
	p.Work()
}

type Tinput struct {
	Fns  []string
	Vals []string
}

type Part2pc struct {
	*fslib.FsLib
	*procclnt.ProcClnt
	me      proc.Tpid
	index   int
	opcode  string
	randstr string
	delay   time.Duration
	args    []string
	done    chan bool
	ti      *Tinput
}

func MkTest2Participant2(args []string) (*Part2pc, error) {
	p := &Part2pc{}
	p.done = make(chan bool)
	p.me = proc.GetPid()
	index, err := strconv.Atoi(args[0])
	if err != nil {
		db.DFatalf("Error strconv index: %v", err)
	}
	p.index = index
	p.opcode = args[1]
	delay, err := time.ParseDuration(args[2])
	if err != nil {
		db.DFatalf("Error parsing duration: %v", err)
	}
	p.delay = delay
	p.randstr = randstr.Hex(16)
	p.FsLib = fslib.MakeFsLib(p.me.String())
	p.ProcClnt = procclnt.MakeProcClnt(p.FsLib)

	log.Printf("%v: Part2pc i %v op %v delay %v\n", p.me, p.index, p.opcode, p.delay)
	p.ti = &Tinput{}
	err = p.GetFileJson(np.MEMFS+"/txni", p.ti)
	if err != nil {
		db.DFatalf("Failed to read txni %v\n", err)
	}

	_, err = twopc.MakeParticipant(p.FsLib, p.ProcClnt, p.me, p, p.opcode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v: error %v", os.Args[0], err)
		os.Exit(1)
	}

	p.Started()

	return p, nil
}

func (p *Part2pc) Prepare() error {
	log.Printf("%v Prepare %v %v", p.me, p.ti.Fns[p.index], p.ti.Vals[p.index])
	_, err := p.PutFile(p.ti.Fns[p.index]+"#"+p.randstr, 0777, np.OWRITE, []byte(p.ti.Vals[p.index]))
	return err
}

func (p *Part2pc) Commit() error {
	if p.opcode == "delayCommit" {
		time.Sleep(p.delay)
	}
	log.Printf("%v Commit %v %v", p.me, p.ti.Fns[p.index], p.ti.Vals[p.index])
	return p.Rename(p.ti.Fns[p.index]+"#"+p.randstr, p.ti.Fns[p.index])
}

func (p *Part2pc) Abort() error {
	log.Printf("%v Abort", p.me)
	return p.Remove(p.ti.Fns[p.index] + "#" + p.randstr)
}

func (p *Part2pc) Done() {
	log.Printf("%v Done", p.me)
	p.done <- true
}

func (p *Part2pc) Work() {
	db.DPrintf("TEST2PC", "Work\n")
	<-p.done
	db.DPrintf("TEST2PC", "exit\n")
	p.Exited(proc.MakeStatus(proc.StatusOK))
}
