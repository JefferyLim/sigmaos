package benchmarks

import (
	"log"
	"path"
	"strconv"
	"time"

	db "ulambda/debug"
	"ulambda/fslib"
	"ulambda/proc"
	"ulambda/procclnt"
	"ulambda/rand"
)

const (
	BURST_BENCH_DIR = "name/burstbench"
)

type BurstBenchmark struct {
	namedAddr []string
	resDir    string
	id        string
	dir       string
	*fslib.FsLib
	*procclnt.ProcClnt
}

func MakeBurstBenchmark(fsl *fslib.FsLib, namedAddr []string, resDir string) *BurstBenchmark {
	b := &BurstBenchmark{}
	b.namedAddr = namedAddr
	b.resDir = resDir
	b.id = rand.String(16)
	b.dir = path.Join(BURST_BENCH_DIR, b.id)
	b.FsLib = fsl
	b.ProcClnt = procclnt.MakeProcClntInit(proc.GenPid(), b.FsLib, "burstbenchmark", namedAddr)
	return b
}

func (b *BurstBenchmark) Run() map[string]*RawResults {
	r := make(map[string]*RawResults)
	pidOffset := 0
	r["burst300"] = b.burst(300, pidOffset)
	return r
}

func (b *BurstBenchmark) setup() {
	b.MkDir(BURST_BENCH_DIR, 0777)
	b.MkDir(b.dir, 0777)
}

func (b *BurstBenchmark) teardown(ps []*proc.Proc) {
	for _, p := range ps {
		if err := b.Evict(p.Pid); err != nil {
			db.DFatalf("Error evict %v: %v", p.Pid, err)
		}
		if status, err := b.WaitExit(p.Pid); !status.IsStatusEvicted() || err != nil {
			db.DFatalf("Error WaitExit: %v %v", status, err)
		}
	}
	b.RmDir(BURST_BENCH_DIR)
}

func (b *BurstBenchmark) burst(N int, pidOffset int) *RawResults {
	b.setup()

	log.Printf("Running BurstBenchmark(%v)...", N)

	// XXX Eventually figure out how to time each start individually.
	rs := MakeRawResults(1)

	ps := []*proc.Proc{}
	for i := 0; i < N; i++ {
		pid := proc.Tpid(b.id + "-" + strconv.Itoa(i+pidOffset))
		p := proc.MakeProcPid(pid, "user/spinner", []string{b.dir})
		p.Ncore = 1
		// Make procs LC to ensure we respect Ncore
		p.Type = proc.T_LC
		ps = append(ps, p)
	}

	defer b.teardown(ps)

	// Start the timer.
	nRPC := b.ReadSeqNo()
	start := time.Now()

	// Spawn a bunch of procs.
	failed, errs := b.SpawnBurst(ps)
	if len(failed) > 0 {
		db.DFatalf("Error Spawn: %v, errors: %v", failed, errs)
	}
	db.DPrintf(db.ALWAYS, "Done spawning")

	// Wait for them all to start
	for i := 0; i < N; i++ {
		db.DPrintf("BENCH", "WaitStart %v", i)
		if err := b.WaitStart(ps[i].Pid); err != nil {
			db.DFatalf("Error WaitStart: %v", err)
			db.DPrintf("BENCH", "Done WaitStart %v", i)
		}
	}
	db.DPrintf(db.ALWAYS, "Done Waiting")
	// Stop the timer
	end := time.Now()
	nRPC = b.ReadSeqNo() - nRPC

	// Calculate throughput, latency, etc.
	elapsed := float64(end.Sub(start).Microseconds())
	throughput := float64(N) / elapsed
	rs.Data[0].set(throughput, elapsed/float64(N), nRPC)

	log.Printf("BurstBenchmark(%v) Done in %vms", N, elapsed/1000.0)

	return rs
}
