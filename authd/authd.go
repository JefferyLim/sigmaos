package authd

import (
	"path"
   
	db "sigmaos/debug"
	"sigmaos/fs"
	"sigmaos/memfssrv"
	"sigmaos/rand"
	sp "sigmaos/sigmap"
	"sigmaos/sigmasrv"

	"sigmaos/procclnt"

	"fmt"
	"io"
    gofs "io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gliderlabs/ssh"
    
    "sigmaos/authd/proto"
	"context"
	"github.com/aws/aws-sdk-go-v2/config"
)

type AuthSrv struct {
	sid      string
	auths    *authMap
	kernelId string
}

func RunAuthSrv(kernelId string) error {
	authsrv := &AuthSrv{}
	authsrv.sid = rand.String(8)
	authsrv.auths = mkAuthMap()
	authsrv.kernelId = kernelId

	db.DPrintf(db.AUTHSRV, "==%v== Creating auth service \n", authsrv.sid)

	mfs, err := memfssrv.MakeMemFs(path.Join(sp.AUTHSRV, "jeff"), sp.AUTHSRVREL)
	if err != nil {
		db.DFatalf("Error MakeMemFs: %v", err)
	}

	ssrv, err := sigmasrv.MakeSigmaSrvMemFs(mfs, authsrv)
	procclnt.MountPids(mfs.SigmaClnt().FsLib, ssrv.MemFs.SigmaClnt().NamedAddr())
	if err != nil {
		db.DPrintf(db.AUTHSRV, "%v", err)
	}
	db.DPrintf(db.AUTHSRV, "==%v== Starting to run authsrv \n", authsrv.sid)

    // This whole process takes around 15 seconds. Unsure how to speed it up
	err = filepath.WalkDir("keys/", func(path string, di gofs.DirEntry, err error) error {
		if !di.IsDir() {
			authorizedKeysBytes, err := os.ReadFile(path)
			if err != nil {
				db.DPrintf(db.AUTHSRV, "Error reading %v", path)
			} else {
				user := strings.Split(path, "/")
				username := user[1]
				
                pubKey, _, _, _, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
				if err != nil {
					db.DPrintf(db.AUTHSRV, "Error parsing key %v", err)
				}

                // Create the user in our struct
				err = authsrv.auths.createUser(username, string(pubKey.Marshal()))
				if err != nil {
					return err
				}

                // Load in the shared aws credential files and search for the specific username  
				cfg, err := config.LoadDefaultConfig(context.TODO(),
					config.WithSharedConfigProfile(username))
				if err != nil {
					db.DFatalf("Failed to load SDK configuration %v", err)
				}

                // Retrieve the necessary credentials
				region := cfg.Region
				creds, err := cfg.Credentials.Retrieve(context.TODO())
				err = authsrv.auths.updateAWS(username, creds.AccessKeyID, creds.SecretAccessKey, region)
				if err != nil {
					db.DFatalf("Failed to update AWS", err)
				}

			}
		}
		return nil
	})

    db.DPrintf(db.JEFF, "DONE LAODING")

	if err != nil {
		return err
	}

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
func (authsrv *AuthSrv) Echo(ctx fs.CtxI, req proto.EchoRequest, rep *proto.EchoResult) error {
	db.DPrintf(db.AUTHSRV, "==%v== Received Echo Request: %v\n", authsrv.sid, req)
	rep.Text = req.Text
	return nil
}

func (authsrv *AuthSrv) Auth(ctx fs.CtxI, req proto.AuthRequest, rep *proto.AuthResult) error {
	db.DPrintf(db.AUTHSRV, "==%v== Received Auth Request: %v\n", authsrv.sid, req)

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

func (authsrv *AuthSrv) Validate(ctx fs.CtxI, req proto.ValidRequest, rep *proto.ValidResult) error {
	db.DPrintf(db.AUTHSRV, "==%v== Received Validate Request: %v\n", authsrv.sid, req)

    _, ok := authsrv.auths.lookupUuid(req.Uuid)
    if ok != nil {
        rep.Ok = false
    }else{
        rep.Ok = true
    }

    return nil

}

func (authsrv *AuthSrv) GetAWS(ctx fs.CtxI, req proto.AWSRequest, rep *proto.AWSResult) error {
	db.DPrintf(db.AUTHSRV, "==%v== Received AWS Request: %v\n", authsrv.sid, req)

	found, ok := authsrv.auths.lookupUuid(req.Uuid)
	if ok == nil {
		rep.Accesskeyid = found.aws_key
		rep.Secretaccesskey = found.aws_secret
		rep.Region = found.aws_region
		db.DPrintf(db.AUTHSRV, "Found: %v\n", found)
		return nil
	}

	return nil
}
