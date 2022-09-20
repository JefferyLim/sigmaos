package leadertest

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"

	"sigmaos/fslib"
	np "sigmaos/ninep"
	"sigmaos/proc"
	"sigmaos/test"
)

func runLeaders(t *testing.T, ts *test.Tstate, sec string) (string, []proc.Tpid) {
	const (
		N = 10
	)
	pids := []proc.Tpid{}

	// XXX use the same dir independent of machine running proc
	ts.RmDir(np.UX + "/" + np.FENCEDIR)

	dir := np.UX + "/~ip/outdir/"
	fn := dir + "out"
	ts.RmDir(dir)
	err := ts.MkDir(dir, 0777)
	_, err = ts.PutFile(fn, 0777, np.OWRITE, []byte{})
	assert.Nil(t, err, "putfile")

	for i := 0; i < N; i++ {
		last := ""
		if i == N-1 {
			last = "last"
		}
		p := proc.MakeProc("user/leadertest-leader", []string{dir, last, sec})
		err = ts.Spawn(p)
		assert.Nil(t, err, "Spawn")

		err = ts.WaitStart(p.Pid)
		assert.Nil(t, err, "WaitStarted")

		pids = append(pids, p.Pid)
	}

	for _, pid := range pids {
		_, err = ts.WaitExit(pid)
		if pid == pids[len(pids)-1] {
			assert.Nil(t, err, "WaitExit")
		}
	}
	return fn, pids
}

func check(t *testing.T, ts *test.Tstate, fn string, pids []proc.Tpid) {
	rdr, err := ts.OpenReader(fn)
	assert.Nil(t, err, "GetFile")
	m := make(map[proc.Tpid]bool)
	last := proc.Tpid("")
	e := np.Tepoch(0)
	err = fslib.JsonReader(rdr, func() interface{} { return new(Config) }, func(a interface{}) error {
		conf := *a.(*Config)
		log.Printf("conf: %v\n", conf)
		if conf.Leader == "" {
			assert.Equal(t, conf.Epoch, e.String())
		} else if last != conf.Leader { // new leader
			assert.Equal(t, conf.Pid, conf.Leader, "new leader")
			_, ok := m[conf.Leader]
			assert.False(t, ok, "pid")
			m[conf.Leader] = true
			last = conf.Leader
			e += 1
			assert.Equal(t, conf.Epoch, e.String())
		}
		return nil
	})
	assert.Nil(t, err, "StreamJson")
	for _, pid := range pids {
		assert.True(t, m[pid], "pids")
	}
}

func TestOldPrimary(t *testing.T) {
	ts := test.MakeTstateAll(t)
	fn, pids := runLeaders(t, ts, "")
	check(t, ts, fn, pids)

	log.Printf("exit\n")

	ts.Shutdown()
}

func TestOldProc(t *testing.T) {
	ts := test.MakeTstateAll(t)
	fn, pids := runLeaders(t, ts, "child")
	check(t, ts, fn, pids)

	log.Printf("exit\n")

	ts.Shutdown()
}
