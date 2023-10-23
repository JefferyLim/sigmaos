package authsrv


import (
	db "sigmaos/debug"
	"sigmaos/rand"
	sp "sigmaos/sigmap"

    "fmt"
    "io"
    "io/ioutil"
    "strings"
    "strconv"

    "github.com/gliderlabs/ssh"
    gossh "golang.org/x/crypto/ssh"
)

type AuthSrv struct {
	sid     string
    auths   *authMap
    port    uint32

}

func RunAuthSrv(port uint32) *AuthSrv {
	authsrv := &AuthSrv{}
    authsrv.sid = rand.String(8)
    authsrv.auths = mkAuthMap()
	authsrv.port = port

	db.DPrintf(db.AUTHSRV, "==%v== Creating auth server \n", authsrv.sid)

	db.DPrintf(db.AUTHSRV, "==%v== Starting to run auth service\n", authsrv.sid)

    ssh.Handle(func(s ssh.Session) {
        authorizedKey := gossh.MarshalAuthorizedKey(s.PublicKey())
        io.WriteString(s, fmt.Sprintf("public key used by %s:\n", s.User()))
        s.Write(authorizedKey)

        // Expect user to be fid-uname-aname
        split := strings.Split(s.User(), "--")
        db.DPrintf(db.JEFF, "split: %v, %v", s.User(), split)

                
        i, err1 := strconv.ParseInt(split[0], 10, 32)
        if( err1 != nil){
            db.DPrintf(db.AUTHSRV, "strconv error %v", err1)
        }

        info := authReq{}
        info.fid = sp.Tfid(uint32(i))
        info.uname = split[1]
        info.aname = split[2]

        check, err := authsrv.auths.lookup(info)
        db.DPrintf(db.AUTHSRV, "authmap: %v:%v\n", check, err)

        var stuff sp.Tfid
        if (err != nil) {
            db.DPrintf(db.AUTHSRV, "can't find associated fid")
        }else{
            stuff, _ = authsrv.auths.authenticate(info)
        }

        io.WriteString(s, fmt.Sprintf("afid:%d public key used by %s:\n", uint32(stuff), s.User()))
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
/*
        // if authentication fails, delete the request if it hasn't been authenticated
        if(equal == false){
            // Expect user to be fid--uname--aname
            split := strings.Split(ctx.User(), "--")
            db.DPrintf(db.JEFF, "deleting split: %v, %v", ctx.User(), split)

                
            i, err1 := strconv.ParseInt(split[0], 10, 32)
            if( err1 != nil){
                db.DPrintf(db.AUTHSRV, "strconv error %v", err1)
            }

            info := authReq{}
            info.fid = sp.Tfid(uint32(i))
            info.uname = split[1]
            info.aname = split[2]

            authsrv.auths.delete(info)
        }
*/
        return equal
    
    })

    listenport := ":" + strconv.FormatUint(uint64(port), 10)
    
    go ssh.ListenAndServe(listenport, nil, publicKeyOption)

    return authsrv
}

func (authsrv * AuthSrv) GetPort() uint32 {
    return authsrv.port
}

type EchoRequest struct {
    Text string
}

type EchoResult struct {
    Text string
}


type AuthRequest struct {
    Fid uint32
    Uname string
    Aname string
}

type AuthResult struct {
    Afid uint32
}


type ValidRequest struct {
    Afid uint32
    Fid uint32
    Uname string
    Aname string
}

type ValidResult struct {
    Ok bool
}

// find meaning of life for request
func (authsrv *AuthSrv) EchoCall(req EchoRequest, rep *EchoResult) error {
	db.DPrintf(db.AUTHSRV, "==%v== Received Echo Request: %v\n", authsrv.sid, req)
	rep.Text = req.Text
	return nil
}

func (authsrv *AuthSrv) AuthCall(req AuthRequest, rep *AuthResult) error {
	db.DPrintf(db.AUTHSRV, "==%v== Received Auth Request: %v\n", authsrv.sid, req)
    
    request := authReq{}
    request.fid = sp.Tfid(req.Fid)
    request.uname = req.Uname
    request.aname = req.Aname

    info, err := authsrv.auths.lookup(request)

    if(err != nil){
        rep.Afid = uint32(authsrv.auths.allocAuth(request))
        db.DPrintf(db.AUTHSRV, "==%v== Allocating Auth Request: %d: %v\n", authsrv.sid, rep.Afid, request)
    }else{
        db.DPrintf(db.AUTHSRV, "==%v== Found AFID: %v\n", authsrv.sid, info) 
        rep.Afid = uint32(info.afid)
    }

    return nil
}

func (authsrv * AuthSrv) ValidateCall(req ValidRequest, rep *ValidResult) error {
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
