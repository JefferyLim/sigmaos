package auth_server

import (
	db "sigmaos/debug"
	"sigmaos/fs"
	"sigmaos/rand"
	sp "sigmaos/sigmap"
	"sigmaos/sigmasrv"

    "fmt"
    "io"
    "os"
    "io/ioutil"

    "github.com/gliderlabs/ssh"
    gossh "golang.org/x/crypto/ssh"

)

// YH:
// Toy server echoing request message

type AuthSrv struct {
	sid string
}

const DEBUG_AUTH_SERVER = "AUTH_SERVER"
const DIR_AUTH_SERVER = sp.NAMED + "example/"
const NAMED_AUTH_SERVER = DIR_AUTH_SERVER + "auth-server"

func RunAuthSrv(public bool) error {
	authsrv := &AuthSrv{rand.String(8)}
	db.DPrintf(DEBUG_AUTH_SERVER, "==%v== Creating auth server \n", authsrv.sid)
	ssrv, err := sigmasrv.MakeSigmaSrvPublic(NAMED_AUTH_SERVER, authsrv, DEBUG_AUTH_SERVER, public)
	if err != nil {
		return err
	}
	db.DPrintf(DEBUG_AUTH_SERVER, "==%v== Starting to run auth service\n", authsrv.sid)

    ssh.Handle(func(s ssh.Session) {
        authorizedKey := gossh.MarshalAuthorizedKey(s.PublicKey())
        io.WriteString(s, fmt.Sprintf("public key used by %s:\n", s.User()))
        s.Write(authorizedKey)
    })

    publicKeyOption := ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
        entries, err := os.ReadDir("./")
        if err == nil {
            for _, e := range entries {
                db.DPrintf(DEBUG_AUTH_SERVER, "%v", e.Name())
            }
        }
        data, err := ioutil.ReadFile("keys/id_agent_test.pub")
        if err != nil {
            db.DPrintf(DEBUG_AUTH_SERVER, "%v", err)
        }

        allowed, _, _, _, err := ssh.ParseAuthorizedKey(data)
        if err != nil {
            db.DPrintf(DEBUG_AUTH_SERVER, "%v", err)
        }

        equal := ssh.KeysEqual(key, allowed)
        db.DPrintf(DEBUG_AUTH_SERVER, "user login attempt: %v:%t", ctx.User(), equal)

        return true
    
    })

    ssh.ListenAndServe(":2222", nil, publicKeyOption)
	return ssrv.RunServer()
}

// find meaning of life for request
func (authsrv *AuthSrv) Auth(ctx fs.CtxI, req AuthRequest, rep *AuthResult) error {
	db.DPrintf(DEBUG_AUTH_SERVER, "==%v== Received Auth Request: %v\n", authsrv.sid, req)
	rep.Text = req.Text
	return nil
}
