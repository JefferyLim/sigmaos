package main

import (
	"os"
	"bufio"
    "net"
	"fmt"
	"strings"
    "sigmaos/authd"

    db "sigmaos/debug"
)

// "API handler" for authsrv
func handler(conn net.Conn, authmap *authd.AuthMap) {
	// will listen for message to process ending in newline (\n)
	message, _ := bufio.NewReader(conn).ReadString('\n')
	// output message received
	fmt.Print("authsrv request", string(message))
	// sample process for string received
	newmessage := strings.ToLower(message)
	
    res1 := strings.Split(newmessage, ":")
		if (res1[0]) == "get" {
			username := res1[1]
			
			found, err := authmap.LookupUname(username)
			if err != nil {
				fmt.Print("Error: ", err)
			}
			fmt.Println("Found: "+ found.String())
			conn.Write([]byte(found.String() + "\n"))
		}
}



func main() {
	if len(os.Args) != 2 {
		db.DFatalf("Usage :%v key path, %d", os.Args[0], len(os.Args))
	}

	authmap, err := authd.RunAuthSrv("goaway", os.Args[1])
	if err != nil {
		db.DFatalf("RunAuthSrv %v err %v\n", os.Args[0], err)
	}

    PORT := ":" + "4444"
    l, err := net.Listen("tcp", PORT)

    if err != nil {
        db.DFatalf("err %v\n", err)
    }

    defer l.Close()

	fmt.Println("Ready...")
    for {
        conn, err := l.Accept()
        if err != nil {
            db.DPrintf(db.TEST, "error accepting")
            continue
        }

        go handler(conn, authmap)
    }

}
