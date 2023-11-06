package authclnt

import (
	db "sigmaos/debug"
    "sigmaos/serr"
    
    "os"
	"net"
	"bytes"
	
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

)

func Auth(uname string) (string, *serr.Err) {

    socket := os.Getenv("SSH_AUTH_SOCK")
    db.DPrintf(db.JEFF, "authclnt/authclnt.go: %v", socket)
    conn, err1 := net.Dial("unix", socket)
    if(err1 != nil){
        db.DPrintf(db.JEFF, "authclnt/authclnt.go net.Dial: %v", err1)
        return "", serr.MkErrError(err1)
    }

    username := uname
    agentClient := agent.NewClient(conn)
    config := &ssh.ClientConfig{
        User: username,
        Auth: []ssh.AuthMethod{
            // Use a callback rather than PublicKeys so we only consult the
            // agent once theremote server wants it.
            ssh.PublicKeysCallback(agentClient.Signers),
        },
    HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    }

    sshc, err1 := ssh.Dial("tcp", "localhost:2222", config)
    if(err1 != nil){
        db.DPrintf(db.JEFF, "authclnt/authclnt.go ssh.Dial: %v", err1)
        return "", serr.MkErrError(err1)
    }

    session, err1 := sshc.NewSession()
    if(err1 != nil){
        db.DPrintf(db.JEFF, "authclnt/authclnt.go sshc.NewSession: %v", err1)
        return "", serr.MkErrError(err1)
    }

    var b bytes.Buffer
    session.Stdout = &b

    session.Run("")
    db.DPrintf(db.TEST, "server: %s", b.String()) 
    
    sshc.Close()

	return b.String(), nil
}

