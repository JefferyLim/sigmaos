package leadertest

import (
	"log"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"

	"sigmaos/fslib"
	"sigmaos/proc"
	sp "sigmaos/sigmap"
	"sigmaos/test"
)

const (
	DIR = sp.NAMED + "outdir"
)

func runLeaders(t *testing.T, ts *test.Tstate, sec string) (string, []proc.Tpid) {
	const (
		N = 10
	)
	pids := []proc.Tpid{}

	ts.RmDir(DIR)
	fn := path.Join(DIR, OUT)

	ts.Remove(LEADERFN)
	err := ts.MkDir(DIR, 0777)
	_, err = ts.PutFile(fn, 0777, sp.OWRITE, []byte{})
	assert.Nil(t, err, "putfile")

	for i := 0; i < N; i++ {
		last := ""
		if i == N-1 {
			last = "last"
		}
		p := proc.MakeProc("leadertest-leader", []string{DIR, last, sec})
		err = ts.Spawn(p)
		assert.Nil(t, err, "Spawn")

		err = ts.WaitStart(p.GetPid())
		assert.Nil(t, err, "WaitStarted")

		pids = append(pids, p.GetPid())
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
	e := sp.Tepoch(0)
	err = fslib.JsonReader(rdr, func() interface{} { return new(Config) }, func(a interface{}) error {
		conf := *a.(*Config)
		log.Printf("conf: %v\n", conf)
		if conf.Leader == proc.Tpid("") && e != 0 {
			assert.Equal(t, conf.Epoch, e)
		} else if last != conf.Leader { // new leader
			assert.Equal(t, conf.Pid, conf.Leader, "new leader")
			_, ok := m[conf.Leader]
			assert.False(t, ok, "pid")
			m[conf.Leader] = true
			last = conf.Leader
			assert.True(t, conf.Epoch > e)
			e = conf.Epoch
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
	ts.Shutdown()
}

func TestOldProc(t *testing.T) {
	ts := test.MakeTstateAll(t)
	fn, pids := runLeaders(t, ts, "child")
	check(t, ts, fn, pids)
	ts.Shutdown()
}
