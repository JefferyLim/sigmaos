package authsrv

import (
	"path"

	db "sigmaos/debug"
	"sigmaos/fs"
	"sigmaos/rand"
	sp "sigmaos/sigmap"
	"sigmaos/sigmasrv"
	"sigmaos/memfssrv"

	"sigmaos/procclnt"

    "fmt"
    "io"
    "io/ioutil"
    "strings"
    "strconv"

    "github.com/gliderlabs/ssh"
    gossh "golang.org/x/crypto/ssh"
    AuthStr "sigmaos/authstructs"
)

type AuthSrv struct {
	sid     string
    auths   *authMap
	kernelId string

}

func RunAuthSrv(kernelId string) error {
	authsrv := &AuthSrv{}
    authsrv.sid = rand.String(8)
    authsrv.auths = mkAuthMap()
	authsrv.kernelId = kernelId

	db.DPrintf(db.AUTHSRV, "==%v== Creating auth server \n", authsrv.sid)

    mfs, err := memfssrv.MakeMemFs(path.Join(sp.AUTHSRV, "jeff"), sp.AUTHSRVREL)
    if err != nil{
		db.DFatalf("Error MakeMemFs: %v", err)
	} 

	ssrv, err := sigmasrv.MakeSigmaSrvMemFs(mfs, authsrv)
    //ssrv, err := sigmasrv.MakeSigmaSrvPublic(sp.AUTHSRV, authsrv, sp.AUTHSRV, false)
	procclnt.MountPids(mfs.SigmaClnt().FsLib, ssrv.MemFs.SigmaClnt().NamedAddr())
	if err != nil {
        db.DPrintf(db.AUTHSRV, "%v", err)
	}
	db.DPrintf(db.AUTHSRV, "==%v== Starting to run auth service\n", authsrv.sid)

    ssh.Handle(func(s ssh.Session) {
        authorizedKey := gossh.MarshalAuthorizedKey(s.PublicKey())
        io.WriteString(s, fmt.Sprintf("public key used by %s:\n", s.User()))
        s.Write(authorizedKey)

        // Expect user to be fid-uname-aname
        split := strings.Split(s.User(), "-")

        info := authReq{}
        i, err := strconv.ParseInt(split[0], 10, 32)
        if err != nil {
            panic(err)
        }

        info.fid = sp.Tfid(uint32(i))
        info.uname = split[1]
        info.aname = split[2]

        check, err := authsrv.auths.lookup(info)
        db.DPrintf(db.AUTHSRV, "authmap: %v:%v\n", check, err)

        if (err != nil) {
            db.DPrintf(db.AUTHSRV, "can't find associated fid")
        }else{
            authsrv.auths.authenticate(info)
        }

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
func (authsrv *AuthSrv) Echo(ctx fs.CtxI, req AuthStr.EchoRequest, rep *AuthStr.EchoResult) error {
	db.DPrintf(db.AUTHSRV, "==%v== Received Echo Request: %v\n", authsrv.sid, req)
	rep.Text = req.Text
	return nil
}


func (authsrv *AuthSrv) Auth(ctx fs.CtxI, req AuthStr.AuthRequest, rep *AuthStr.AuthResult) error {
	db.DPrintf(db.AUTHSRV, "==%v== Received Auth Request: %v\n", authsrv.sid, req)
    
    request := authReq{}
    request.fid = sp.Tfid(req.Fid)
    request.uname = req.Uname
    request.aname = req.Aname

    info, err := authsrv.auths.lookup(request)

    if(err != nil){
        rep.Afid = uint32(authsrv.auths.allocAuth(request))
        db.DPrintf(db.AUTHSRV, "==%v== Allocating Auth Request: %d\n", authsrv.sid, rep.Afid)
    }else{
        db.DPrintf(db.AUTHSRV, "==%v== Found AFID: %v\n", authsrv.sid, info) 
        rep.Afid = uint32(info.afid)
    }

    return nil
}

func (authsrv * AuthSrv) Validate(ctx fs.CtxI, req AuthStr.ValidRequest, rep *AuthStr.ValidResult) error {
    db.DPrintf(db.AUTHSRV, "==%v== Received Validate Request: %v\n", authsrv.sid, req)
    
    request := authReq{}
    request.fid = sp.Tfid(req.Fid)
    request.uname = req.Uname
    request.aname = req.Aname

    info, err := authsrv.auths.lookup(request)
    
    if(err !=  nil){
        rep.Ok = false
    }

    if(info.afid == sp.Tfid(req.Afid) && info.authenticated == true){
        rep.Ok = true
    }else{
        rep.Ok = false
    }

    return nil

}



// find meaning of life for request
func (authsrv *AuthSrv) EchoCall(req AuthStr.EchoRequest, rep *AuthStr.EchoResult) error {
	db.DPrintf(db.AUTHSRV, "==%v== Received Echo Request: %v\n", authsrv.sid, req)
	rep.Text = req.Text
	return nil
}


func (authsrv *AuthSrv) AuthCall(req AuthStr.AuthRequest, rep *AuthStr.AuthResult) error {
	db.DPrintf(db.AUTHSRV, "==%v== Received Auth Request: %v\n", authsrv.sid, req)
    
    request := authReq{}
    request.fid = sp.Tfid(req.Fid)
    request.uname = req.Uname
    request.aname = req.Aname

    info, err := authsrv.auths.lookup(request)

    if(err != nil){
        rep.Afid = uint32(authsrv.auths.allocAuth(request))
        db.DPrintf(db.AUTHSRV, "==%v== Allocating Auth Request: %d\n", authsrv.sid, rep.Afid)
    }else{
        db.DPrintf(db.AUTHSRV, "==%v== Found AFID: %v\n", authsrv.sid, info) 
        rep.Afid = uint32(info.afid)
    }

    return nil
}

func (authsrv * AuthSrv) ValidateCall(req AuthStr.ValidRequest, rep *AuthStr.ValidResult) error {
    db.DPrintf(db.AUTHSRV, "==%v== Received Validate Request: %v\n", authsrv.sid, req)
    
    request := authReq{}
    request.fid = sp.Tfid(req.Fid)
    request.uname = req.Uname
    request.aname = req.Aname

    info, err := authsrv.auths.lookup(request)
    
    if(err !=  nil){
        rep.Ok = false
    }

    if(info.afid == sp.Tfid(req.Afid) && info.authenticated == true){
        rep.Ok = true
    }else{
        rep.Ok = false
    }

    return nil

}
