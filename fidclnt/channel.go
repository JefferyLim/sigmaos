package fidclnt

import (
	"fmt"

	"sigmaos/path"
	"sigmaos/protclnt"
	"sigmaos/serr"
	sp "sigmaos/sigmap"
)

// The channel associated with an fid, which connects to an object at
// a server.
type Channel struct {
	pc    *protclnt.ProtClnt
	path  path.Path
	qids  []*sp.Tqid
	uname sp.Tuname
}

func makeChannel(pc *protclnt.ProtClnt, uname sp.Tuname, path path.Path, qs []*sp.Tqid) *Channel {
	c := &Channel{}
	c.pc = pc
	c.path = path
	c.qids = qs
	c.uname = uname
	return c
}

func (c *Channel) String() string {
	return fmt.Sprintf("{ Path %v Qids %v }", c.path, c.qids)
}

func (c *Channel) Uname() sp.Tuname {
	return c.uname
}

func (c *Channel) Path() path.Path {
	return c.path
}

func (c *Channel) SetPath(p path.Path) {
	c.path = p
}

func (c *Channel) Version() sp.TQversion {
	return c.Lastqid().Tversion()
}

func (c *Channel) Copy() *Channel {
	qids := make([]*sp.Tqid, len(c.qids))
	copy(qids, c.qids)
	return makeChannel(c.pc, c.uname, c.path.Copy(), qids)
}

func (c *Channel) add(name string, q *sp.Tqid) {
	c.path = append(c.path, name)
	c.qids = append(c.qids, q)
}

// empty path = ""
func (c *Channel) AddN(qs []*sp.Tqid, path path.Path) {
	if len(path) == 0 {
		path = append(path, "")
	}
	for i, q := range qs {
		c.add(path[i], q)
	}
}

func (c *Channel) Lastqid() *sp.Tqid {
	return c.qids[len(c.qids)-1]
}

// Simulate network partition to server that exports path
func (c *Channel) Disconnect() *serr.Err {
	return c.pc.Disconnect()
}

func (c *Channel) Servers() sp.Taddrs {
	return c.pc.Servers()
}
