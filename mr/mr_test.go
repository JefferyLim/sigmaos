package mr_test

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"ulambda/coordmgr"
	"ulambda/fslib"
	"ulambda/kernel"
	"ulambda/mr"
	np "ulambda/ninep"
	"ulambda/procclnt"
)

const OUTPUT = "par-mr.out"

func Compare(fsl *fslib.FsLib) {
	cmd := exec.Command("sort", "seq-mr.out")
	var out1 bytes.Buffer
	cmd.Stdout = &out1
	err := cmd.Run()
	if err != nil {
		log.Printf("cmd err %v\n", err)
	}
	cmd = exec.Command("sort", OUTPUT)
	var out2 bytes.Buffer
	cmd.Stdout = &out2
	err = cmd.Run()
	if err != nil {
		log.Printf("cmd err %v\n", err)
	}
	b1 := out1.Bytes()
	b2 := out2.Bytes()
	if len(b1) != len(b2) {
		log.Fatalf("Output files have different length\n")
	}
	for i, v := range b1 {
		if v != b2[i] {
			log.Fatalf("Buf %v diff %v %v\n", i, v, b2[i])
			break
		}
	}
}

type Tstate struct {
	*procclnt.ProcClnt
	*fslib.FsLib
	t           *testing.T
	s           *kernel.System
	nreducetask int
}

func makeTstate(t *testing.T, nreducetask int) *Tstate {
	var err error
	ts := &Tstate{}
	ts.t = t
	ts.s, ts.FsLib, err = kernel.MakeSystemAll("mr-wc-test", "..")
	assert.Nil(t, err, "Start")
	ts.ProcClnt = procclnt.MakeProcClntInit(ts.FsLib, fslib.Named())
	ts.nreducetask = nreducetask

	mr.InitCoordFS(ts.FsLib, nreducetask)

	os.Remove(OUTPUT)

	return ts
}

func (ts *Tstate) prepareJob() {
	// Put names of input files in name/mr/m
	files, err := ioutil.ReadDir("../input/")
	if err != nil {
		log.Fatalf("Readdir %v\n", err)
	}
	for _, f := range files {
		// remove mapper output directory from previous run
		ts.RmDir("name/ux/~ip/m-" + f.Name())
		n := mr.MDIR + "/" + f.Name()
		if _, err := ts.PutFile(n, []byte(n), 0777, np.OWRITE); err != nil {
			log.Fatalf("PutFile %v err %v\n", n, err)
		}
	}
}

func (ts *Tstate) checkJob() {
	file, err := os.OpenFile(OUTPUT, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("Couldn't open output file\n")
	}
	defer file.Close()

	// XXX run as a proc?
	for i := 0; i < ts.nreducetask; i++ {
		r := strconv.Itoa(i)
		data, err := ts.ReadFile(mr.ROUT + r)
		if err != nil {
			log.Fatalf("ReadFile %v err %v\n", r, err)
		}
		_, err = file.Write(data)
		if err != nil {
			log.Fatalf("Write err %v\n", err)
		}
	}

	Compare(ts.FsLib)
}

func runN(t *testing.T, crash, crashCoord string) {
	const NReduce = 2
	ts := makeTstate(t, NReduce)

	ts.prepareJob()

	cm := coordmgr.StartCoords(ts.FsLib, ts.ProcClnt, "bin/user/mr-coord", []string{strconv.Itoa(NReduce), "bin/user/mr-m-wc", "bin/user/mr-r-wc", crash, crashCoord})

	cm.Wait()

	ts.checkJob()

	ts.s.Shutdown(ts.FsLib)
}

func TestOne(t *testing.T) {
	runN(t, "NO", "NO")
}

func TestCrashTaskOnly(t *testing.T) {
	runN(t, "YES", "NO")
}

func TestCrashCoordOnly(t *testing.T) {
	runN(t, "NO", "YES")
}

func TestCrashTaskAndCoord(t *testing.T) {
	runN(t, "YES", "YES")
}
