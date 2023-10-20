package authsrv

import (
	db "sigmaos/debug"
	"sigmaos/fs"
	"sigmaos/rand"
	sp "sigmaos/sigmap"
	"sigmaos/sigmasrv"

    "fmt"
    "io"
    "io/ioutil"

    "github.com/gliderlabs/ssh"
    gossh "golang.org/x/crypto/ssh"

)

type AuthSrv struct {
	sid     string
}

func RunAuthSrv(public bool) error {
	authsrv := &AuthSrv{rand.String(8)}
	db.DPrintf(db.AUTHSRV, "==%v== Creating auth server \n", authsrv.sid)

    ssrv, err := sigmasrv.MakeSigmaSrv(sp.AUTHSRV, authsrv, sp.AUTHSRV)
	if err != nil {
        db.DPrintf(db.AUTHSRV, "%v", err)
	}
	db.DPrintf(db.AUTHSRV, "==%v== Starting to run auth service\n", authsrv.sid)

    ssh.Handle(func(s ssh.Session) {
        authorizedKey := gossh.MarshalAuthorizedKey(s.PublicKey())
        io.WriteString(s, fmt.Sprintf("public key used by %s:\n", s.User()))
        s.Write(authorizedKey)
    })

    publicKeyOption := ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
        data, err := ioutil.ReadFile("keys/id_agent_test.pub")
        if err != nil {
            db.DPrintf(db.AUTHSRV, "%v", err)
        }

        allowed, _, _, _, err := ssh.ParseAuthorizedKey(data)
        if err != nil {
            db.DPrintf(db.AUTHSRV, "%v", err)
        }

        equal := ssh.KeysEqual(key, allowed)
        db.DPrintf(db.AUTHSRV, "user login attempt: %v:%t", ctx.User(), equal)
        return equal
    
    })

    go ssh.ListenAndServe(":2222", nil, publicKeyOption)

    err = ssrv.RunServer()
    return nil
}

// find meaning of life for request
func (authsrv *AuthSrv) Auth(ctx fs.CtxI, req AuthRequest, rep *AuthResult) error {
	db.DPrintf(db.AUTHSRV, "==%v== Received Auth Request: %v\n", authsrv.sid, req)
	rep.Text = req.Text
	return nil
}
