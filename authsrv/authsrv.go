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

    "os"
	"path/filepath"
    "fmt"
    "io"
    "strings"

    "github.com/gliderlabs/ssh"
    //gossh "golang.org/x/crypto/ssh"
    AuthStr "sigmaos/authstructs"
    //"github.com/google/uuid"

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
	procclnt.MountPids(mfs.SigmaClnt().FsLib, ssrv.MemFs.SigmaClnt().NamedAddr())
	if err != nil {
        db.DPrintf(db.AUTHSRV, "%v", err)
	}
	db.DPrintf(db.AUTHSRV, "==%v== Starting to run auth service\n", authsrv.sid)

		err = filepath.Walk("keys/", func(path string, info os.FileInfo, err error) error {
			if !info.IsDir() {
				authorizedKeysBytes, err := os.ReadFile(path)
				if err != nil {
					db.DPrintf(db.AUTHSRV, "Error reading %v", path)
				}else{
					pubKey, _, _, _, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
					if err != nil {
						db.DPrintf(db.AUTHSRV, "Error parsing key %v", err)
					}
					user := strings.Split(path, "/")
                    username := user[1]

                    authsrv.auths.createUser(username, string(pubKey.Marshal()))
				}	
			}
			return nil
		})

    // SSH handler function for when a user is authenticated
    ssh.Handle(func(s ssh.Session) {
        info := authReq{}
        info.fid = sp.Tfid(uint32(0))
        info.uname = s.User()
        info.aname = s.User()
            
        uuid, err := authsrv.auths.createUUID(s.User())
        if err == nil {
            db.DPrintf(db.AUTHSRV, "UUID created: %v\n", uuid)
        }
            
        //check, err := authsrv.auths.lookup(info)

        if (err != nil) {
            db.DPrintf(db.AUTHSRV, "can't find associated fid")
        }else{
        	db.DPrintf(db.AUTHSRV, "ssh handle auths.lookup: %v:%v\n", "hi", err)
        	//authsrv.auths.authenticate(info)
        }

        io.WriteString(s, fmt.Sprintf("%s", uuid))

    })

    publicKeyOption := ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
        if authsrv.auths.authmap[ctx.User()].pubkey == string(key.Marshal()) {    
			db.DPrintf(db.AUTHSRV, "user login success: %v:%v", ctx.User(), key)
        	return true
		}
		
        return false
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
/*
    info, err := authsrv.auths.lookup(request)

    if(err != nil){
        rep.Afid = uint32(authsrv.auths.allocAuth(request))
        db.DPrintf(db.AUTHSRV, "==%v== Allocating Auth Request: %d\n", authsrv.sid, rep.Afid)
    }else{
        db.DPrintf(db.AUTHSRV, "==%v== Found AFID: %v\n", authsrv.sid, info) 
        rep.Afid = uint32(info.afid)
    }
*/
    return nil
}

func (authsrv * AuthSrv) Validate(ctx fs.CtxI, req AuthStr.ValidRequest, rep *AuthStr.ValidResult) error {
    db.DPrintf(db.AUTHSRV, "==%v== Received Validate Request: %v\n", authsrv.sid, req)
    
    request := authReq{}
    request.fid = sp.Tfid(req.Fid)
    request.uname = req.Uname
    request.aname = req.Aname
/*
    info, err := authsrv.auths.lookup(request)
    
    if(err !=  nil){
        rep.Ok = false
    }

    if(info.afid == sp.Tfid(req.Afid) && info.authenticated == true){
        rep.Ok = true
    }else{
        rep.Ok = false
    }
*/
    return nil

}
