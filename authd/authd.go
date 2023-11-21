package authd

import (
	"errors"
	"path"
	"net"
	"bufio"
	db "sigmaos/debug"
	"sigmaos/fs"
	"sigmaos/memfssrv"
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

	"context"
	"github.com/aws/aws-sdk-go-v2/config"
	"sigmaos/authd/proto"
)

type Authd struct {
	Sid      string
	Auths    *AuthMap
	KernelId string
}

func RunAuthd(kernelId string, authd *Authd) error {
	db.DPrintf(db.AUTHD, "==%v== Creating authd service \n", kernelId)

	mfs, err := memfssrv.MakeMemFs(path.Join(sp.AUTHD, "jeff"), sp.AUTHDREL)
	if err != nil {
		db.DFatalf("Error MakeMemFs: %v", err)
	}

	ssrv, err := sigmasrv.MakeSigmaSrvMemFs(mfs, authd)
	procclnt.MountPids(mfs.SigmaClnt().FsLib, ssrv.MemFs.SigmaClnt().NamedAddr())
	if err != nil {
		db.DPrintf(db.AUTHD, "%v", err)
	}

	err = ssrv.RunServer()

	return nil
}

func RunAuthSrv(kernelId string, path string) (*AuthMap, error) {
	authmap := MkAuthMap()
	
	db.DPrintf(db.AUTHD, "==%v== Starting to run authsrv \n", kernelId)

	// This whole process takes around 15 seconds. Unsure how to speed it up
	err := filepath.WalkDir(path, func(path string, di gofs.DirEntry, err error) error {
		if !di.IsDir() {
			authorizedKeysBytes, err := os.ReadFile(path)
			if err != nil {
				db.DPrintf(db.AUTHD, "Error reading %v", path)
			} else {
				user := strings.Split(path, "/")
				username := user[1]

				pubKey, _, _, _, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
				if err != nil {
					db.DPrintf(db.AUTHD, "Error parsing key %v", err)
				}

				// Create the user in our struct
				err = authmap.CreateUser(username, string(pubKey.Marshal()))
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
				err = authmap.UpdateAWS(username, creds.AccessKeyID, creds.SecretAccessKey, region)
				if err != nil {
					db.DFatalf("Failed to update AWS", err)
				}

			}
		}
		return nil	
	})

	if err != nil {
		return nil, err
	}

	// SSH handler function for when a user is authenticated
	ssh.Handle(func(s ssh.Session) {
		uuid, err := authmap.CreateUUID(s.User())
		if err == nil {
			db.DPrintf(db.AUTHD, "UUID created: %v\n", uuid)
		}
		io.WriteString(s, fmt.Sprintf("%s", uuid))

	})

	publicKeyOption := ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
        db.DPrintf(db.AUTHD, "user login attempt: %v", ctx.User())
		if authmap.authmap[ctx.User()].pubkey == string(key.Marshal()) {
			db.DPrintf(db.AUTHD, "user login success: %v:%v", ctx.User(), key)
			return true
		}

		return false
	})

	go ssh.ListenAndServe(":2222", nil, publicKeyOption)

	return authmap, nil
}

// find meaning of life for request
func (authd *Authd) Echo(ctx fs.CtxI, req proto.EchoRequest, rep *proto.EchoResult) error {
	db.DPrintf(db.AUTHD, "==%v== Received Echo Request: %v\n", authd.Sid, req)
	rep.Text = req.Text
	return nil
}

func (authd *Authd) Auth(ctx fs.CtxI, req proto.AuthRequest, rep *proto.AuthResult) error {
	db.DPrintf(db.AUTHD, "==%v== Received Auth Request: %v\n", authd.Sid, req)
	return nil
}

func (authd *Authd) Validate(ctx fs.CtxI, req proto.ValidRequest, rep *proto.ValidResult) error {
	db.DPrintf(db.AUTHD, "==%v== Received Validate Request: %v\n", authd.Sid, req)
    
	_, ok := authd.Auths.LookupUuid(req.Uuid)
	if ok != nil {
		// check online service
		user,err := onlineSync(req.Uname)
		
		if err == nil {
			authd.Auths.CreateUser(req.Uname, "")
			authd.Auths.UpdateAWS(req.Uname, user.aws_key, user.aws_secret, user.aws_region)
			authd.Auths.UpdateUUID(req.Uname, user.uuid)
		
			rep.Ok = true
			return nil
		}


		rep.Ok = false
	} else {
		rep.Ok = true
	}

	return nil

}

func (authd *Authd) GetAWS(ctx fs.CtxI, req proto.AWSRequest, rep *proto.AWSResult) error {
	db.DPrintf(db.AUTHD, "==%v== Received AWS Request: %v\n", authd.Sid, req)

	found, ok := authd.Auths.LookupUuid(req.Uuid)

	if ok == nil {
		rep.Accesskeyid = found.aws_key
		rep.Secretaccesskey = found.aws_secret
		rep.Region = found.aws_region
		db.DPrintf(db.AUTHD, "Found: %v\n", found)
		return nil
	}

	return nil
}


func onlineSync(username string) (*AuthUser, error){
	c, err := net.Dial("tcp", "localhost:4444")
	if err != nil {
		return nil, errors.New("uhoh")
	}

	user := &AuthUser{}
	
	text := "get:" + username + ":"
	fmt.Fprintf(c, text+"\n")
	
	message, _ := bufio.NewReader(c).ReadString('\n')

	info := strings.Split(message, ":")
	
	if(len(info) != 5){

		return nil, errors.New("uhoh")
	}
	user.uuid = info[0]
	user.aws_key = info[1]
	user.aws_secret = info[2]
	user.aws_region = info[3]

	fmt.Print("sresult: ",  message)

	return user, nil
	
}
