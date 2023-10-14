package authsrv_test

import (
    "os"
    "net"
     gopath "path"
	"bytes"

	"github.com/stretchr/testify/assert"
	auth "sigmaos/authsrv"
	"sigmaos/fslib"
	"sigmaos/rpcclnt"
	"sigmaos/test"
    db "sigmaos/debug"
    sp "sigmaos/sigmap"
	"testing"

    "golang.org/x/crypto/ssh"
    "golang.org/x/crypto/ssh/agent"

)

func TestAuthSrvRPC(t *testing.T) {
	// start server
	ts := test.MakeTstateAll(t)

    sts, err := ts.GetDir(sp.AUTHSRV)
    assert.Nil(t, err)
    db.DPrintf(db.TEST, "authsrv %v\n", sp.Names(sts))


    fn := gopath.Join(sp.AUTHSRV, sts[0].Name)
    // create a RPC client and query server
	rpcc, err := rpcclnt.MkRPCClnt([]*fslib.FsLib{ts.FsLib}, fn)
	assert.Nil(t, err, "RPC client should be created properly")
	arg := auth.AuthRequest{Text: "Hello World!"}
	res := auth.AuthResult{}
	err = rpcc.RPC("AuthSrv.Auth", &arg, &res)
	assert.Nil(t, err, "RPC call should succeed")
	assert.Equal(t, "Hello World!", res.Text)

    // Stop server
	assert.Nil(t, ts.Shutdown())
}

func TestAuthSrvSSH(t *testing.T) {
    // start server
    ts := test.MakeTstateAll(t)

    socket := os.Getenv("SSH_AUTH_SOCK")
    conn, err := net.Dial("unix", socket)
    assert.Nil(t, err, "Error dialing to unix socket %s", socket)

    agentClient := agent.NewClient(conn)
    config := &ssh.ClientConfig{
        User: "Jeff",
        Auth: []ssh.AuthMethod{
            // Use a callback rather than PublicKeys so we only consult the
            // agent once theremote server wants it.
            ssh.PublicKeysCallback(agentClient.Signers),
        },
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    }

    sshc, err := ssh.Dial("tcp", "localhost:2222", config)
    assert.Nil(t, err, "failure to ssh: %v", err)

	session, err := sshc.NewSession()
	assert.Nil(t, err, "Failed to create session: %v", err)

	var b bytes.Buffer
	

	session.Stdout = &b

	session.Run("")
	db.DPrintf(db.TEST, "server: %s", b.String())    

	sshc.Close()

    assert.Nil(t, ts.Shutdown())

}

