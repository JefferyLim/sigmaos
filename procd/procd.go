package procd

import (
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	//	"github.com/sasha-s/go-deadlock"

	db "ulambda/debug"
	"ulambda/fslib"
	"ulambda/fslibsrv"
	"ulambda/linuxsched"
	"ulambda/namespace"
	np "ulambda/ninep"
	"ulambda/perf"
	"ulambda/proc"
	"ulambda/procclnt"
	"ulambda/rand"
)

type Procd struct {
	mu         sync.Mutex
	fs         *ProcdFs
	realmbin   string    // realm path from which to pull/run bins.
	spawnChan  chan bool // Indicates a proc has been spawned on this procd.
	stealChan  chan bool // Indicates there is work to be stolen.
	done       bool
	addr       string
	procs      map[proc.Tpid]Tstatus
	coreBitmap []bool
	coresAvail proc.Tcore
	perf       *perf.Perf
	group      sync.WaitGroup
	procclnt   *procclnt.ProcClnt
	*fslib.FsLib
	*fslibsrv.MemFs
}

func RunProcd(realmbin string) {
	pd := &Procd{}
	pd.realmbin = realmbin

	pd.procs = make(map[proc.Tpid]Tstatus)
	pd.coreBitmap = make([]bool, linuxsched.NCores)
	pd.coresAvail = proc.Tcore(linuxsched.NCores)

	// Must set core affinity before starting CPU Util measurements
	pd.setCoreAffinity()

	pd.perf = perf.MakePerf("PROCD")
	defer pd.perf.Done()

	pd.makeFs()

	// Set up FilePriorityBags and create name/runq
	pd.spawnChan = make(chan bool)
	pd.stealChan = make(chan bool)

	pd.addr = pd.MyAddr()

	pd.MemFs.GetStats().MonitorCPUUtil()

	// Make namespace isolation dir.
	os.MkdirAll(namespace.NAMESPACE_DIR, 0777)

	// Make a directory in which to put stealable procs.
	pd.MkDir(np.PROCD_WS, 0777)

	pd.Work()
}

func (pd *Procd) getProcStatus(pid proc.Tpid) (Tstatus, bool) {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	st, ok := pd.procs[pid]
	return st, ok
}

func (pd *Procd) setProcStatus(pid proc.Tpid, st Tstatus) {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	pd.procs[pid] = st
}

func (pd *Procd) deleteProc(pid proc.Tpid) {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	delete(pd.procs, pid)
}

func (pd *Procd) spawnProc(a *proc.Proc) {
	pd.setProcStatus(a.Pid, PROC_QUEUED)

	pd.spawnChan <- true
}

func (pd *Procd) makeProc(a *proc.Proc) *Proc {
	p := &Proc{}
	p.pd = pd
	p.init(a)
	return p
}

// Evict all procs running in this procd
func (pd *Procd) evictProcsL() {
	for pid, status := range pd.procs {
		if status == PROC_RUNNING {
			pd.procclnt.EvictProcd(pd.addr, pid)
		}
	}
}

func (pd *Procd) Done() {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	pd.done = true
	pd.perf.Done()
	pd.evictProcsL()
	close(pd.spawnChan)
}

func (pd *Procd) readDone() bool {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	return pd.done
}

// XXX Statsd information?
// Check if this procd instance is able to satisfy a job's constraints.
// Trivially true when not benchmarking.
func (pd *Procd) satisfiesConstraintsL(p *proc.Proc) bool {
	// If we have enough cores to run this job...
	if pd.coresAvail >= p.Ncore {
		return true
	}
	return false
}

// Update resource accounting information.
func (pd *Procd) decrementResourcesL(p *proc.Proc) {
	pd.coresAvail -= p.Ncore
}

// Update resource accounting information.
func (pd *Procd) incrementResources(p *proc.Proc) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	pd.incrementResourcesL(p)
}

func (pd *Procd) incrementResourcesL(p *proc.Proc) {
	pd.coresAvail += p.Ncore
}

// Tries to get a runnable proc if it fits on this procd.
func (pd *Procd) tryGetRunnableProc(procPath string) (*proc.Proc, error) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	p, err := pd.readRunqProc(procPath)
	// Proc may have been stolen
	if err != nil {
		db.DPrintf("PROCD_ERR", "Error getting RunqProc: %v", err)
		return nil, err
	}
	// See if the proc fits on this procd.
	if pd.satisfiesConstraintsL(p) {
		// Proc may have been stolen
		if ok := pd.claimProc(procPath); !ok {
			return nil, nil
		}
		// Update resource accounting.
		pd.decrementResourcesL(p)
		return p, nil
	} else {
		db.DPrintf("PROCD", "RunqProc %v didn't satisfy constraints", procPath)
	}
	return nil, nil
}

func (pd *Procd) getProc() (*proc.Proc, error) {
	var p *proc.Proc
	// First try and get any LC procs, else get a BE proc.
	runqs := []string{np.PROCD_RUNQ_LC, np.PROCD_RUNQ_BE}
	// Try local procd first.
	for _, runq := range runqs {
		runqPath := path.Join(np.PROCD, pd.MyAddr(), runq)
		_, err := pd.ProcessDir(runqPath, func(st *np.Stat) (bool, error) {
			newProc, err := pd.tryGetRunnableProc(path.Join(runqPath, st.Name))
			if err != nil {
				db.DPrintf("PROCD_ERR", "Error getting runnable proc: %v", err)
				return false, nil
			}
			// We claimed a proc successfully, so stop.
			if newProc != nil {
				p = newProc
				return true, nil
			}
			// Couldn't claim a proc, so keep looking.
			return false, nil
		})
		if err != nil {
			return nil, err
		}
		if p != nil {
			return p, nil
		}
	}
	// Try to steal from other procds.
	_, err := pd.ProcessDir(np.PROCD_WS, func(st *np.Stat) (bool, error) {
		procPath := path.Join(np.PROCD_WS, st.Name)
		newProc, err := pd.tryGetRunnableProc(procPath + "/")
		if err != nil {
			db.DPrintf("PROCD_ERR", "Error readRunqProc in Procd.getProc: %v", err)
			// Remove the symlink, as it must have already been claimed.
			pd.Remove(procPath)
			return false, nil
		}
		if newProc != nil {
			db.DPrintf("PROCD", "Stole proc: %v", newProc)
			p = newProc
			// Remove the ws symlink.
			if err := pd.Remove(procPath); err != nil {
				db.DPrintf("PROCD_ERR", "Error Remove symlink after claim: %v", err)
			}
			return true, nil
		}
		return false, nil
	})
	return p, err
}

func (pd *Procd) allocCores(n proc.Tcore) []uint {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	cores := []uint{}
	for i := 0; i < len(pd.coreBitmap); i++ {
		// If lambda asks for 0 cores, run on any core
		if n == proc.C_DEF {
			cores = append(cores, uint(i))
		} else {
			if !pd.coreBitmap[i] {
				pd.coreBitmap[i] = true
				cores = append(cores, uint(i))
				n -= 1
				if n == 0 {
					break
				}
			}
		}
	}
	return cores
}

func (pd *Procd) freeCores(cores []uint) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	for _, i := range cores {
		pd.coreBitmap[i] = false
	}
}

// Try to download a proc bin from s3.
func (pd *Procd) tryDownloadProcBin(uxBinPath, s3BinPath string) error {
	// Copy the binary from s3 to a temporary file.
	tmppath := path.Join(uxBinPath + "-tmp-" + rand.String(16))
	if err := pd.CopyFile(s3BinPath, tmppath); err != nil {
		return err
	}
	// Rename the temporary file.
	if err := pd.Rename(tmppath, uxBinPath); err != nil {
		// If another procd (or another thread on this procd) already completed the
		// download, then we consider the download successful. Any other error
		// (e.g. ux crashed) is unexpected.
		if !np.IsErrExists(err) {
			return err
		}
		// If someone else completed the download before us, remove the temp file.
		pd.Remove(tmppath)
	}
	return nil
}

// Check if we need to download a new version of the binary.
func (pd *Procd) needToDownload(uxBinPath, s3BinPath string) bool {
	// If we can't stat the bin through ux, we try to download it. This might be
	// overly-aggressive in the event that the ~local ux crashes, but it should
	// still be correct.
	st1, err := pd.Stat(uxBinPath)
	if err != nil {
		return true
	}
	// Stat the s3 version of the bin.
	st2, err := pd.Stat(s3BinPath)
	if err != nil {
		db.DFatalf("Couldn't stat s3 bin: %v", err)
	}
	// If the "last modified" time of the s3-backed binary is more recent that
	// the "last modified" time of the ux-backed binary, we need to download the
	// new version. Otherwise, continue as normal.
	if st1.Mtime < st2.Mtime {
		db.DPrintf(db.ALWAYS, "s3 bin is newer (%v < %v), need to download", st1.Mtime, st2.Mtime)
		db.DPrintf("PROCD", "s3 bin is newer (%v < %v), need to download", st1.Mtime, st2.Mtime)
		// Remove the old version.
		pd.Remove(uxBinPath)
		return true
	}
	return false
}

// XXX Cleanup on procd crashes?
func (pd *Procd) downloadProcBin(program string) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	uxBinPath := path.Join(np.UXBIN, program)
	s3BinPath := path.Join(np.S3, "~ip", pd.realmbin, program)

	// If we already downloaded the program & it is up-to-date, return.
	if !pd.needToDownload(uxBinPath, s3BinPath) {
		return
	}

	db.DPrintf("PROCD", "Need to download %v", program)

	// May need to retry if ux crashes.
	RETRIES := 1000
	for i := 0; i < RETRIES && !pd.done; i++ {
		// Return if successful. Else, retry
		if err := pd.tryDownloadProcBin(uxBinPath, s3BinPath); err == nil {
			return
		} else {
			db.DPrintf("PROCD_ERR", "Error tryDownloadProcBin [%v]: %v", s3BinPath, err)
		}
	}
	db.DFatalf("Couldn't download proc bin %v in over %v retries", program, RETRIES)
}

func (pd *Procd) runProc(p *Proc) {
	// Register running proc
	pd.setProcStatus(p.Pid, PROC_RUNNING)

	// Allocate dedicated cores for this lambda to run on.
	cores := pd.allocCores(p.attr.Ncore)

	// Download the bin from s3, if it isn't already cached locally.
	pd.downloadProcBin(p.Program)

	// Run the proc.
	p.run(cores)

	// Free resources and dedicated cores.
	pd.freeCores(cores)
	pd.incrementResources(p.attr)

	// Deregister running procs
	pd.deleteProc(p.Pid)
}

func (pd *Procd) setCoreAffinity() {
	// XXX Currently, we just set the affinity for all available cores since Linux
	// seems to do a decent job of avoiding moving things around too much.
	m := &linuxsched.CPUMask{}
	for i := uint(0); i < linuxsched.NCores; i++ {
		m.Set(i)
	}
	linuxsched.SchedSetAffinityAllTasks(os.Getpid(), m)
}

// Wait for a new proc to be spawned at this procd, or for a stealing
// opportunity to present itself.
func (pd *Procd) waitSpawnOrSteal() {
	select {
	case _, _ = <-pd.spawnChan:
		db.DPrintf("PROCD", "done waiting, a proc was spawned")
	case _, _ = <-pd.stealChan:
		db.DPrintf("PROCD", "done waiting, a proc can be stolen")
	}
}

// Worker runs one proc a time. If the proc it runs has Ncore == 0, then
// another worker is spawned to take this one's place. This worker will then
// exit once it finishes runing the proc.
func (pd *Procd) worker() {
	defer pd.group.Done()
	for !pd.readDone() {
		db.DPrintf("PROCD", "Try to get proc.")
		p, error := pd.getProc()
		// If there were no runnable procs, wait and try again.
		if error == nil && p == nil {
			db.DPrintf("PROCD", "No procs found, waiting.")
			pd.waitSpawnOrSteal()
			continue
		}
		if error != nil && (errors.Is(error, io.EOF) ||
			(np.IsErrUnreachable(error) && strings.Contains(np.ErrPath(error), "no mount"))) {
			continue
		}
		if error != nil {
			if np.IsErrNotfound(error) {
				db.DPrintf("PROCD_ERR", "cond file not found: %v", error)
				return
			}
			pd.perf.Done()
			db.DFatalf("Procd GetProc error %v, %v\n", p, error)
		}
		db.DPrintf("PROCD", "Got proc %v", p)
		localProc := pd.makeProc(p)
		err := pd.fs.running(localProc)
		if err != nil {
			pd.perf.Done()
			db.DFatalf("Procd pub running error %v %T\n", err, err)
		}
		// If this proc doesn't require cores, start another worker to take our
		// place so user apps don't deadlock.
		replaced := false
		if p.Ncore == 0 {
			replaced = true
			pd.group.Add(1)
			go pd.worker()
		}
		pd.runProc(localProc)
		if replaced {
			return
		}
	}
}

func (pd *Procd) Work() {
	pd.group.Add(1)
	go func() {
		defer pd.group.Done()
		pd.Serve()
		pd.Done()
		pd.MemFs.Done()
	}()
	go pd.workStealingMonitor()
	go pd.offerStealableProcs()
	// The +1 is needed so procs trying to spawn a new proc never deadlock if this
	// procd is full
	NWorkers := linuxsched.NCores + 1
	for i := uint(0); i < NWorkers; i++ {
		pd.group.Add(1)
		go pd.worker()
	}
	pd.group.Wait()
}
