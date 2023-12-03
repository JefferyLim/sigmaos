package netsrv

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"sigmaos/container"
	db "sigmaos/debug"
	"sigmaos/proc"
	"sigmaos/serr"
	"sigmaos/sessp"
	sps "sigmaos/sigmaprotsrv"
)

type WriteF func(*sessp.FcallMsg, []byte, *bufio.Writer) *serr.Err
type ReadF func(rdr io.Reader) (sessp.Tseqno, *sessp.FcallMsg, *serr.Err)

type NetServer struct {
	addr       string
	sesssrv    sps.SessServer
	writefcall WriteF
	readframe  ReadF
	l          net.Listener
}

func MakeNetServer(ss sps.SessServer, address string, m WriteF, u ReadF) *NetServer {
	srv := &NetServer{sesssrv: ss, writefcall: m, readframe: u}

	cert, err := tls.LoadX509KeyPair("certs/sigmaos.crt", "certs/sigmaos.key")
	if err != nil {
		db.DFatalf("LoadX509KeyPair error: %v", err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}

	// Create and start the main server listener
	var l net.Listener
	//l, err := net.Listen("tcp", address)
	l, err = tls.Listen("tcp", address, config)
	if err != nil {
		db.DFatalf("Listen error: %v", err)
	}
	a, err := container.QualifyAddr(l.Addr().String())
	if err != nil {
		db.DFatalf("QualifyAddr %v error: %v", a, err)
	}
	srv.addr = a
	srv.l = l
	db.DPrintf(db.PORT, "listen %v myaddr %v\n", address, a)
	go srv.runsrv(l)
	return srv
}

func (srv *NetServer) MyAddr() string {
	return srv.addr
}

func (srv *NetServer) CloseListener() error {
	db.DPrintf(db.ALWAYS, "Close %v\n", srv.addr)
	return srv.l.Close()
}

func (srv *NetServer) runsrv(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			db.DPrintf(db.ALWAYS, "%v: Accept err %v", proc.GetPid(), err)
			return
		}
		db.DPrintf(db.NETSRV, "accept %v %v\n", l, conn)
		MakeSrvConn(srv, conn)
	}
}

func (srv *NetServer) String() string {
	return fmt.Sprintf("{ addr: %v }", srv.addr)
}
