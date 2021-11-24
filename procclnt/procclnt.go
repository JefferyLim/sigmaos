package procclnt

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"sync"

	db "ulambda/debug"
	"ulambda/fslib"
	"ulambda/named"
	"ulambda/namespace"
	np "ulambda/ninep"
	"ulambda/proc"
	"ulambda/seccomp"
	usync "ulambda/sync"
)

const (
	// name for dir where procs live. May not refer to name/pids
	// because proc.PidDir may change it.  A proc refers to itself
	// using "pids/<pid>", where pid is the proc's PID.
	PIDS = "pids"

	// Files/directories in "pids/<pid>":
	START_WAIT = "start-sem"
	EVICT_WAIT = "evict-sem"
	RET_STATUS = "status-pipe"
	CHILD      = "childs" // directory with children's pids

	MAXSTATUS = 1000
)

type ProcClnt struct {
	mu sync.Mutex
	*fslib.FsLib
	pid    string
	piddir string
	exited string
}

func makeProcClnt(fsl *fslib.FsLib, piddir, pid string) *ProcClnt {
	clnt := &ProcClnt{}
	clnt.FsLib = fsl
	clnt.pid = pid
	clnt.piddir = piddir
	return clnt
}

// ========== SPAWN ==========

// XXX cleanup on failure
func (clnt *ProcClnt) Spawn(p *proc.Proc) error {
	if clnt.hasExited() == p.Pid {
		return fmt.Errorf("Spawn: called after Exited")
	}

	// Select which queue to put the job in
	piddir := proc.PidDir(p.Pid)
	if err := clnt.Mkdir(piddir, 0777); err != nil {
		log.Fatalf("%v: Spawn mkdir pid %v err %v\n", db.GetName(), piddir, err)
		return err
	}
	if clnt.piddir != p.PidDir {
		log.Printf("%v: spawn clnt %v make piddir %v\n", db.GetName(), clnt.piddir, p.PidDir)
		if err := clnt.Mkdir(p.PidDir, 0777); err != nil {
			log.Fatalf("%v: Spawn new piddir %v err %v\n", db.GetName(), p.PidDir, err)
			return err
		}
		piddir = p.PidDir + "/" + p.Pid
		if err := clnt.Mkdir(piddir, 0777); err != nil {
			log.Fatalf("%v: Spawn mkdir pid %v err %v\n", db.GetName(), piddir, err)
			return err
		}
	}

	err := clnt.MakePipe(piddir+"/"+RET_STATUS, 0777)
	if err != nil {
		log.Fatalf("%v: MakePipe %v err %v\n", db.GetName(), RET_STATUS, err)
	}

	semStart := usync.MakeSemaphore(clnt.FsLib, piddir+"/"+START_WAIT)
	semStart.Init()

	semEvict := usync.MakeSemaphore(clnt.FsLib, piddir+"/"+EVICT_WAIT)
	semEvict.Init()

	d := piddir + "/" + CHILD
	if err := clnt.Mkdir(d, 0777); err != nil {
		log.Fatalf("%v: Spawn mkdir childs %v err %v\n", db.GetName(), d, err)
		return err
	}

	// Add pid to my children
	f := PIDS + "/" + proc.GetPid() + "/" + CHILD + "/" + p.Pid
	if err := clnt.MakeFile(f, 0777, np.OWRITE, []byte{}); err != nil {
		log.Fatalf("%v: Spawn mkfile child %v err %v\n", db.GetName(), f, err)
		return err
	}

	b, err := json.Marshal(p)
	if err != nil {
		log.Fatalf("Error marshal: %v", err)
		return err
	}

	err = clnt.WriteFile(path.Join(named.PROCDDIR+"/~ip", named.PROC_CTL_FILE), b)
	if err != nil {
		log.Printf("Error WriteFile in ProcClnt.Spawn: %v", err)
		return err
	}

	return nil
}

// ========== WAIT ==========

// Parent calls WaitStart() to wait until the child proc has
// started. If the proc doesn't exist, return immediately.
func (clnt *ProcClnt) WaitStart(pid string) error {
	piddir := proc.PidDir(pid)
	semStart := usync.MakeSemaphore(clnt.FsLib, piddir+"/"+START_WAIT)
	semStart.Down()
	return nil
}

// Parent calls WaitExited() to wait until child proc has exited. If
// the proc doesn't exist, return immediately.  After collecting
// return status, parent cleans up the child and parent removes the
// child from its list of children.
func (clnt *ProcClnt) WaitExit(pid string) (string, error) {
	piddir := proc.PidDir(pid)

	// log.Printf("%v: waitexit %v\n", db.GetName(), piddir)

	if _, err := clnt.Stat(piddir); err != nil {
		return "", err
	}

	// Remove pid from my children
	f := PIDS + "/" + proc.GetPid() + "/" + CHILD + "/" + path.Base(pid)
	if err := clnt.Remove(f); err != nil {
		log.Fatalf("Error Remove %v in WaitExit: %v", f, err)
	}

	fn := piddir + "/" + RET_STATUS
	fd, err := clnt.Open(piddir+"/"+RET_STATUS, np.OREAD)
	if err != nil {
		log.Fatalf("Error Open %v err %v", fn, err)
	}

	b, err := clnt.Read(fd, MAXSTATUS)
	if err != nil {
		log.Printf("Read %v err %v", fn, err)
		return "", err
	}

	err = clnt.Close(fd)
	if err != nil {
		log.Printf("Close %v err %v", fn, err)
	}

	clnt.destroyProc(piddir)

	return string(b), nil

}

// Proc pid waits for eviction notice from procd.
func (clnt *ProcClnt) WaitEvict(pid string) error {
	piddir := proc.PidDir(pid)
	semEvict := usync.MakeSemaphore(clnt.FsLib, piddir+"/"+EVICT_WAIT)
	semEvict.Down()
	return nil
}

// ========== STARTED ==========

// Proc pid marks itself as started.
func (clnt *ProcClnt) Started(pid string) error {
	dir := proc.PidDir(pid)
	semStart := usync.MakeSemaphore(clnt.FsLib, dir+"/"+START_WAIT)
	semStart.Up()
	// Isolate the process namespace
	newRoot := os.Getenv("NEWROOT")
	if err := namespace.Isolate(newRoot); err != nil {
		log.Fatalf("Error Isolate in clnt.Started: %v", err)
	}
	// Load a seccomp filter.
	seccomp.LoadFilter()
	return nil
}

// ========== EXITED ==========

// Proc pid mark itself as exited. Typically Exited() is called by
// proc pid, but if the proc crashes, procd calls Exited() on behalf
// of the failed proc. The exited proc abandons any chidren it may
// have.  If itself is an abandoned child, then it cleans up itself;
// otherwise the parent will do it.
//
// Exited() should be called *once* per proc, but procd's procclnt may
// call Exited() for different procs.
func (clnt *ProcClnt) Exited(pid string, status string) error {
	piddir := proc.PidDir(pid)

	// log.Printf("%v: exited %v\n", db.GetName(), piddir)

	if clnt.setExited(pid) == pid {
		log.Printf("%v: Exited called after exited %v\n", db.GetName(), piddir)
		return fmt.Errorf("Exited: called more than once for pid %v", pid)
	}

	// Abandon any children I may have left.
	clnt.abandonChildren(piddir)

	fn := piddir + "/" + RET_STATUS
	fd, err := clnt.Open(fn, np.OWRITE)
	if err != nil {
		// parent has abandoned me; clean myself up
		// log.Printf("%v: Error Open %v err %v", db.GetName(), fn, err)
		clnt.destroyProc(piddir)
	} else {
		_, err = clnt.Write(fd, []byte(status))
		if err != nil {
			log.Printf("Write %v err %v", fn, err)
		}

		err = clnt.Close(fd)
		if err != nil {
			log.Printf("Close %v err %v", fn, err)
		}
	}

	// log.Printf("%v: exited done %v\n", db.GetName(), piddir)

	return nil
}

// ========== EVICT ==========

// Procd notifies a proc that it will be evicted using Evict.
// XXX handle piddir not existing
func (clnt *ProcClnt) Evict(pid string) error {
	piddir := proc.PidDir(pid)
	semEvict := usync.MakeSemaphore(clnt.FsLib, piddir+"/"+EVICT_WAIT)
	semEvict.Up()
	return nil
}

// ========== Helpers ==========

// Remove status from children to indicate we don't care
func (clnt *ProcClnt) abandonChildren(piddir string) {
	cpids := piddir + "/" + CHILD
	sts, err := clnt.ReadDir(cpids)
	if err != nil {
		log.Fatalf("abandonChildren %v err : %v", cpids, err)
	}
	for _, st := range sts {
		clnt.abandonChild(PIDS + "/" + st.Name)
	}
}

// Abandon child
func (clnt *ProcClnt) abandonChild(piddir string) {
	f := piddir + "/" + RET_STATUS
	err := clnt.Remove(f)
	if err != nil {
		log.Printf("%v: Remove %v err %v\n", db.GetName(), f, err)
	}
}

// Clean up proc
func (clnt *ProcClnt) destroyProc(piddir string) {
	// log.Printf("%v: destroy %v\n", db.GetName(), piddir)
	if err := clnt.RmDir(piddir); err != nil {
		s, _ := clnt.SprintfDir(piddir)
		log.Fatalf("%v: RmDir %v err %v %v", db.GetName(), piddir, err, s)
	}
}

func (clnt *ProcClnt) hasExited() string {
	clnt.mu.Lock()
	defer clnt.mu.Unlock()
	return clnt.exited
}

func (clnt *ProcClnt) setExited(pid string) string {
	clnt.mu.Lock()
	defer clnt.mu.Unlock()
	r := clnt.exited
	clnt.exited = pid
	return r
}
