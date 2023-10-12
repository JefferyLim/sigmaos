package auth_server_test

import (
	"github.com/stretchr/testify/assert"
	"path"
	dbg "sigmaos/debug"
	auth "sigmaos/auth_server"
	"sigmaos/fslib"
	"sigmaos/proc"
	"sigmaos/rand"
	"sigmaos/rpcclnt"
	"sigmaos/test"
	"strconv"
	"testing"
)

type TstateAuth struct {
	*test.Tstate
	jobname string
	pid     proc.Tpid
}

func makeTstateAuth(t *testing.T) (*TstateAuth, error) {
	jobname := rand.String(8)
	jobdir := path.Join(auth.DIR_AUTH_SERVER, jobname)
	var err error
	tse := &TstateAuth{}
	tse.jobname = jobname
	tse.Tstate = test.MakeTstateAll(t)
	tse.MkDir(auth.DIR_AUTH_SERVER, 0777)
	if err = tse.MkDir(jobdir, 0777); err != nil {
		return nil, err
	}
	// Start proc
	p := proc.MakeProc("example-auth", []string{strconv.FormatBool(test.Overlays)})
	p.SetMcpu(proc.Tmcpu(1000))
	if _, errs := tse.SpawnBurst([]*proc.Proc{p}, 2); len(errs) > 0 {
		dbg.DFatalf("Error burst-spawnn proc %v: %v", p, errs)
		return nil, err
	}
	if err = tse.WaitStart(p.GetPid()); err != nil {
		dbg.DFatalf("Error spawn proc %v: %v", p, err)
		return nil, err
	}
	tse.pid = p.GetPid()
	return tse, nil
}

func (tse *TstateAuth) Stop() error {
	if err := tse.Evict(tse.pid); err != nil {
		return err
	}
	if _, err := tse.WaitExit(tse.pid); err != nil {
		return err
	}
	return tse.Shutdown()
}

func TestAuth(t *testing.T) {
	// start server
	tse, err := makeTstateAuth(t)
	assert.Nil(t, err, "Test server should start properly %v", err)

	// create a RPC client and query server
	rpcc, err := rpcclnt.MkRPCClnt([]*fslib.FsLib{tse.FsLib}, auth.NAMED_AUTH_SERVER)
	assert.Nil(t, err, "RPC client should be created properly")
	arg := auth.AuthRequest{Text: "Hello World!"}
	res := auth.AuthResult{}
	err = rpcc.RPC("AuthSrv.Auth", &arg, &res)
	assert.Nil(t, err, "RPC call should succeed")
	assert.Equal(t, "Hello World!", res.Text)

	// Stop server
	assert.Nil(t, tse.Stop())
}

