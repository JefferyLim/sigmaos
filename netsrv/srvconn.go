package netsrv

import (
	"bufio"
	"net"

	db "ulambda/debug"
	np "ulambda/ninep"
	"ulambda/npcodec"
)

const (
	Msglen = 64 * 1024
)

type SrvConn struct {
	conn       net.Conn
	wireCompat bool
	br         *bufio.Reader
	bw         *bufio.Writer
	replies    chan *np.Fcall
	sesssrv    np.SessServer
	sessid     np.Tsession
}

func MakeSrvConn(srv *NetServer, conn net.Conn) *SrvConn {
	c := &SrvConn{conn,
		srv.wireCompat,
		bufio.NewReaderSize(conn, Msglen),
		bufio.NewWriterSize(conn, Msglen),
		make(chan *np.Fcall),
		srv.sesssrv,
		0,
	}
	go c.writer()
	go c.reader()
	return c
}

func (c *SrvConn) Close() {
	db.DPrintf("NETSRV", "%v Close conn\n", c.sessid)
	c.conn.Close()
}

func (c *SrvConn) Src() string {
	return c.conn.RemoteAddr().String()
}

func (c *SrvConn) Dst() string {
	return c.conn.LocalAddr().String()
}

func (c *SrvConn) reader() {
	db.DPrintf("NETSRV", "%v (%v) Reader conn from %v\n", c.sessid, c.Dst(), c.Src())
	for {
		frame, err := npcodec.ReadFrame(c.br)
		if err != nil {
			db.DPrintf("NETSRV_ERR", "%v ReadFrame err %v\n", c.sessid, err)
			// session mgr will timeout this session eventually
			c.conn.Close()
			return
		}
		var fcall *np.Fcall
		if c.wireCompat {
			fcall, err = npcodec.UnmarshalFcallWireCompat(frame)
		} else {
			fcall, err = npcodec.UnmarshalFcall(frame)
		}
		if err != nil {
			db.DPrintf("NETSRV_ERR", "%v reader from %v: bad fcall: ", c.sessid, c.Src(), err)
			// XXX tell sesssrv that conn closed?
			return
		}
		db.DPrintf("NETSRV", "srv req %v\n", fcall)
		if c.sessid == 0 {
			c.sessid = fcall.Session
			conn := &np.Conn{c, c.replies}
			if err := c.sesssrv.Register(fcall.Session, conn); err != nil {
				db.DPrintf("NETSRV_ERR", "Sess %v closed\n", c.sessid)
				fc := np.MakeFcallReply(fcall, err.Rerror())
				c.replies <- fc
				close(conn.Replies)
				return
			}
		} else if c.sessid != fcall.Session {
			db.DFatalf("reader: two sess (%v and %v) on conn?\n", c.sessid, fcall.Session)
		}
		c.sesssrv.SrvFcall(fcall)
	}
}

// XXX Should we close with other error conditions?
func (c *SrvConn) writer() {
	for {
		fcall, ok := <-c.replies
		if !ok {
			db.DPrintf("NETSRV", "%v writer: close conn from %v\n", c.sessid, c.Src())
			c.conn.Close()
			return
		}
		db.DPrintf("NETSRV", "rep %v\n", fcall)
		var writableFcall np.WritableFcall
		if c.wireCompat {
			writableFcall = fcall.ToWireCompatible()
		} else {
			writableFcall = fcall
		}
		if err := npcodec.MarshalFcall(writableFcall, c.bw); err != nil {
			db.DPrintf("NETSRV_ERR", "%v writer %v err %v\n", c.sessid, c.Src(), err)
			continue
		}
		if error := c.bw.Flush(); error != nil {
			db.DPrintf("NETSRV_ERR", "flush %v to %v err %v", fcall, c.Src(), error)
		}
	}
}
