package npsrv

import (
	"fmt"
	"log"
	"net"

	db "ulambda/debug"
	"ulambda/npclnt"
)

type NpConn interface {
	Connect(net.Conn) NpAPI
}

type NpServer struct {
	npc        NpConn
	addr       string
	replicated bool
	replConfig *NpServerReplConfig
}

type NpServerReplConfig struct {
	HeadAddr string
	TailAddr string
	PrevAddr string
	NextAddr string
	HeadChan *npclnt.NpChan
	TailChan *npclnt.NpChan
	PrevChan *npclnt.NpChan
	NextChan *npclnt.NpChan
	*npclnt.NpClnt
}

func MakeNpServer(npc NpConn, address string) *NpServer {
	return MakeReplicatedNpServer(npc, address, false, nil)
}

// TODO: establish connections with other servers.
func MakeReplicatedNpServer(npc NpConn, address string, replicated bool, config *NpServerReplConfig) *NpServer {
	var emptyConfig *NpServerReplConfig
	if replicated {
		db.DLPrintf("9PSRV", "starting replicated server: %v\n", config)
		clnt := npclnt.MakeNpClnt()
		emptyConfig = &NpServerReplConfig{"", "", "", "", nil, nil, nil, nil, clnt}
	}
	srv := &NpServer{npc, "", replicated, emptyConfig}
	var l net.Listener
	l, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal("Listen error:", err)
	}
	srv.addr = l.Addr().String()
	if replicated {
		srv.reloadConfig(config)
	}
	db.DLPrintf("9PCHAN", "listen %v  myaddr %v\n", address, srv.addr)
	go srv.runsrv(l)
	return srv
}

func (srv *NpServer) reloadConfig(cfg *NpServerReplConfig) {
	// TODO locking, trigger resends, etc.
	if srv.replConfig.HeadAddr != cfg.HeadAddr {
		srv.connectToReplica(&srv.replConfig.HeadChan, cfg.HeadAddr)
		srv.replConfig.HeadAddr = cfg.HeadAddr
	}
	if srv.replConfig.TailAddr != cfg.TailAddr {
		srv.connectToReplica(&srv.replConfig.TailChan, cfg.TailAddr)
		srv.replConfig.TailAddr = cfg.TailAddr
	}
	if srv.replConfig.PrevAddr != cfg.PrevAddr {
		srv.connectToReplica(&srv.replConfig.PrevChan, cfg.PrevAddr)
		srv.replConfig.PrevAddr = cfg.PrevAddr
	}
	if srv.replConfig.NextAddr != cfg.NextAddr {
		srv.connectToReplica(&srv.replConfig.NextChan, cfg.NextAddr)
		srv.replConfig.NextAddr = cfg.NextAddr
	}
}

func (srv *NpServer) connectToReplica(c **npclnt.NpChan, addr string) {
	*c = srv.replConfig.MakeNpChan(addr)
}

func (srv *NpServer) MyAddr() string {
	return srv.addr
}

func (srv *NpServer) runsrv(l net.Listener) {
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("Accept error: ", err)
		}

		// If we aren't replicated or we're at the end of the chain, create a normal
		// channel.
		if !srv.replicated {
			MakeChannel(srv.npc, conn)
		} else {
			// Else, make a relay channel which forwards calls along the chain.
			db.DLPrintf("9PCHAN", "relay chan from %v -> %v\n", conn.RemoteAddr(), srv.addr)
			MakeRelayChannel(srv.npc, conn, srv.replConfig.NextChan, srv.isTail())
		}
	}
}

func (srv *NpServer) isHead() bool {
	return srv.addr == srv.replConfig.HeadAddr
}

func (srv *NpServer) isTail() bool {
	return srv.addr == srv.replConfig.TailAddr
}

func (srv *NpServer) isChainConn(addr net.Addr) bool {
	return addr.String() == srv.replConfig.PrevAddr
}

func (srv *NpServer) String() string {
	return fmt.Sprintf("{ addr: %v replicated: %v config: %v }", srv.addr, srv.replicated, srv.replConfig)
}

func (c *NpServerReplConfig) String() string {
	return fmt.Sprintf("{ head: %v tail: %v prev: %v next: %v}", c.HeadAddr, c.TailAddr, c.PrevAddr, c.NextAddr)
}
