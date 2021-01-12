package fsclnt

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"time"

	db "ulambda/debug"
	np "ulambda/ninep"
	"ulambda/npclnt"
	"ulambda/npcodec"
)

const (
	// zero channel to named
	Stdin  = 0
	Stdout = 1
	// Stderr = 2
)

const MAXFD = 20

const MAXSYMLINK = 4

type FdState struct {
	offset np.Toffset
	fid    np.Tfid
}

type FsClient struct {
	fds   []FdState
	fids  map[np.Tfid]*Channel
	npc   *npclnt.NpClnt
	mount *Mount
	next  np.Tfid
	Proc  string
}

func MakeFsClient(proc string, debug bool) *FsClient {
	fsc := &FsClient{}
	fsc.fds = make([]FdState, 0, MAXFD)
	fsc.fids = make(map[np.Tfid]*Channel)
	fsc.mount = makeMount()
	fsc.npc = npclnt.MakeNpClnt(debug)
	fsc.next = 1
	fsc.Proc = proc
	db.Debug = debug
	rand.Seed(time.Now().UnixNano())
	return fsc
}

func (fsc *FsClient) String() string {
	str := fmt.Sprintf("Fsclnt table:\n")
	str += fmt.Sprintf("fds %v\n", fsc.fds)
	for k, v := range fsc.fids {
		str += fmt.Sprintf("fid %v chan %v\n", k, v)
	}
	return str
}

func (fsc *FsClient) npch(fid np.Tfid) *npclnt.NpChan {
	return fsc.fids[fid].npch
}

// // XXX use gob?
func InitFsClient(args []string) (*FsClient, error) {
	log.Printf("InitFsClient: %v\n", args)
	if len(args) < 2 {
		return nil, errors.New("Missing len and program")
	}
	n, err := strconv.Atoi(args[0])
	if err != nil {
		return nil, errors.New("Bad arg len")
	}
	if n < 1 {
		return nil, errors.New("Missing program")
	}
	a := args[1 : n+1] // skip len and +1 for program name
	fids := args[n+1:]
	fsc := MakeFsClient(a[0], false)
	log.Printf("Args %v fids %v\n", a, fids)
	if fid, err := fsc.Attach(":1111", ""); err == nil {
		err := fsc.Mount(fid, "name")
		if err != nil {
			return nil, errors.New("Mount error")
		}
		_, err = fsc.Open("name/consoled/console", np.OREAD)
		if err != nil {
			return nil, errors.New("Open error")
		}
		_, err = fsc.Open("name/consoled/console", np.OWRITE)
		if err != nil {
			return nil, errors.New("Open error")
		}

		log.Printf("fsc %v\n", fsc)
	}

	// for _, f := range fids {
	// 	var uf fid.Ufid
	// 	err := json.Unmarshal([]byte(f), &uf)
	// 	if err != nil {
	// 		return nil, nil, errors.New("Bad fid")
	// 	}
	// 	fsc.findfd(&uf)
	// }

	return fsc, nil
}

func (fsc *FsClient) findfd(nfid np.Tfid) int {
	for fd, fdst := range fsc.fds {
		if fdst.fid == np.NoFid {
			fsc.fds[fd].offset = 0
			fsc.fds[fd].fid = nfid
			return fd
		}
	}
	// no free one
	fsc.fds = append(fsc.fds, FdState{0, nfid})
	return len(fsc.fds) - 1
}

func (fsc *FsClient) allocFid() np.Tfid {
	fid := fsc.next
	fsc.next += 1
	return fid
}

func (fsc *FsClient) lookup(fd int) (np.Tfid, error) {
	if fsc.fds[fd].fid == np.NoFid {
		return np.NoFid, errors.New("Non-existing")
	}
	return fsc.fds[fd].fid, nil
}

func (fsc *FsClient) lookupSt(fd int) (*FdState, error) {
	if fsc.fds[fd].fid == np.NoFid {
		return nil, errors.New("Non-existing")
	}
	return &fsc.fds[fd], nil
}

func (fsc *FsClient) Mount(fid np.Tfid, path string) error {
	_, ok := fsc.fids[fid]
	if !ok {
		return errors.New("Unknown fid")
	}
	db.DPrintf("Mount %v at %v %v\n", fid, path, fsc.npch(fid))
	fsc.mount.add(np.Split(path), fid)
	return nil
}

func (fsc *FsClient) Close(fd int) error {
	fid, err := fsc.lookup(fd)
	if err != nil {
		return err
	}
	err = fsc.npch(fid).Clunk(fid)
	if err == nil {
		fsc.fds[fd].fid = np.NoFid
	}
	return err
}

func (fsc *FsClient) AttachChannel(fid np.Tfid, server string, p []string) (*Channel, error) {
	reply, err := fsc.npc.Attach(server, fid, p)
	if err != nil {
		return nil, err
	}
	ch := fsc.npc.MakeNpChan(server)
	return makeChannel(ch, p, []np.Tqid{reply.Qid}), nil
}

func (fsc *FsClient) Attach(server string, path string) (np.Tfid, error) {
	p := np.Split(path)
	fid := fsc.allocFid()
	ch, err := fsc.AttachChannel(fid, server, p)
	if err != nil {
		return np.NoFid, err
	}
	fsc.fids[fid] = ch
	db.DPrintf("Attach -> fid %v %v %v\n", fid, fsc.fids[fid], fsc.fids[fid].npch)
	return fid, nil
}

func (fsc *FsClient) clone(fid np.Tfid) (np.Tfid, error) {
	fid1 := fsc.allocFid()
	_, err := fsc.npch(fid).Walk(fid, fid1, nil)
	if err != nil {
		// XXX free fid
		return np.NoFid, err
	}
	fsc.fids[fid1] = fsc.fids[fid].copyChannel()
	return fid1, err
}

func (fsc *FsClient) closeFid(fid np.Tfid) {
	err := fsc.npch(fid).Clunk(fid)
	if err != nil {
		log.Printf("closeFid clunk failed %v\n", err)
	}
	delete(fsc.fids, fid)
}

func (fsc *FsClient) walkOne(path []string) (np.Tfid, int, error) {
	fid, rest := fsc.mount.resolve(path)
	db.DPrintf("walkOne: mount -> %v %v\n", fid, rest)
	if fid == np.NoFid {
		return np.NoFid, 0, errors.New("Unknown file")

	}
	fid1, err := fsc.clone(fid)
	if err != nil {
		return np.NoFid, 0, err
	}
	defer fsc.closeFid(fid1)

	fid2 := fsc.allocFid()
	reply, err := fsc.npch(fid1).Walk(fid1, fid2, rest)
	if err != nil {
		return np.NoFid, 0, err
	}
	todo := len(rest) - len(reply.Qids)
	db.DPrintf("walkOne rest %v -> %v %v", rest, reply.Qids, todo)

	fsc.fids[fid2] = fsc.fids[fid1].copyChannel()
	fsc.fids[fid2].addn(reply.Qids, rest)
	return fid2, todo, nil
}

func isRemoteTarget(target string) bool {
	return strings.Contains(target, ":")
}

// XXX more robust impl
func splitTarget(target string) (string, string) {
	parts := strings.Split(target, ":")
	server := parts[0] + ":" + parts[1] + ":" + parts[2] + ":" + parts[3]
	return server, parts[len(parts)-1]
}

func (fsc *FsClient) autoMount(target string, path []string) error {
	db.DPrintf("automount %v to %v\n", target, path)
	server, _ := splitTarget(target)
	fid, err := fsc.Attach(server, "")
	if err != nil {
		log.Fatal("Attach error: ", err)
	}
	return fsc.Mount(fid, np.Join(path))
}

func (fsc *FsClient) walkMany(path []string, resolve bool) (np.Tfid, error) {
	for i := 0; i < MAXSYMLINK; i++ {
		fid, todo, err := fsc.walkOne(path)
		if err != nil {
			return fid, err
		}
		qid := fsc.fids[fid].lastqid()

		// if todo == 0 and !resolve, don't resolve symlinks, so
		// that the client remove a symlink
		if qid.Type == np.QTSYMLINK && (todo > 0 || (todo == 0 && resolve)) {
			target, err := fsc.Readlink(fid)
			if err != nil {
				return np.NoFid, err
			}
			i := len(path) - todo
			rest := path[i:]
			if isRemoteTarget(target) {
				err = fsc.autoMount(target, path[:i])
				if err != nil {
					return np.NoFid, err
				}
				path = append(path[:i], rest...)
			} else {
				path = append(np.Split(target), rest...)

			}
		} else {
			return fid, err

		}
	}
	return np.NoFid, errors.New("too many iterations")
}

func (fsc *FsClient) Create(path string, perm np.Tperm, mode np.Tmode) (int, error) {
	db.DPrintf("Create %v\n", path)
	p := np.Split(path)
	dir := p[0 : len(p)-1]
	base := p[len(p)-1]
	fid, err := fsc.walkMany(dir, true)
	if err != nil {
		return -1, err
	}
	reply, err := fsc.npch(fid).Create(fid, base, perm, mode)
	if err != nil {
		return -1, err
	}
	fsc.fids[fid].add(base, reply.Qid)
	fd := fsc.findfd(fid)
	return fd, nil
}

func (fsc *FsClient) Mkdir(path string, perm np.Tperm, mode np.Tmode) (int, error) {
	perm = perm | np.DMDIR
	return fsc.Create(path, perm, mode)
}

func (fsc *FsClient) CreateAt(dfd int, name string, perm np.Tperm, mode np.Tmode) (int, error) {
	db.DPrintf("CreateAt %v at %v\n", name, dfd)
	fid, err := fsc.lookup(dfd)
	if err != nil {
		return -1, err
	}
	fid1, err := fsc.clone(fid)
	if err != nil {
		return -1, err
	}
	reply, err := fsc.npch(fid1).Create(fid1, name, perm, mode)
	if err != nil {
		return -1, err
	}
	fsc.fids[fid1].add(name, reply.Qid)
	fd := fsc.findfd(fid1)
	return fd, nil
}

func (fsc *FsClient) Symlink(target string, link string, lperm np.Tperm) error {
	lperm = lperm | np.DMSYMLINK
	fd, err := fsc.Create(link, lperm, np.OWRITE)
	if err != nil {
		return err
	}
	_, err = fsc.Write(fd, []byte(target))
	if err != nil {
		return err
	}
	return fsc.Close(fd)
}

func (fsc *FsClient) SymlinkAt(dfd int, target string, link string, lperm np.Tperm) error {
	lperm = lperm | np.DMSYMLINK
	fd, err := fsc.CreateAt(dfd, link, lperm, np.OWRITE)
	_, err = fsc.Write(fd, []byte(target))
	if err != nil {
		return err
	}
	return fsc.Close(fd)
}

func (fsc *FsClient) Pipe(path string, perm np.Tperm) error {
	db.DPrintf("Mkpipe %v\n", path)
	p := np.Split(path)
	dir := p[0 : len(p)-1]
	base := p[len(p)-1]
	fid, err := fsc.walkMany(dir, true)
	if err != nil {
		return err
	}
	_, err = fsc.npch(fid).Mkpipe(fid, base, perm)
	return err
}

// XXX update pathname associated with fid in Channel
func (fsc *FsClient) Rename(old string, new string) error {
	db.DPrintf("Rename %v %v\n", old, new)
	fid, err := fsc.walkMany(np.Split(old), true)
	if err != nil {
		return err
	}
	fid1, rest := fsc.mount.resolve(np.Split(new))
	if fid1 == np.NoFid {
		return errors.New("Bad destination")

	}
	// XXX check fid is at same server?
	// XXX deal with symbolic names on rest
	st := &np.Stat{}
	st.Name = strings.Join(rest, "/")
	_, err = fsc.npch(fid).Wstat(fid, st)
	return err
}

func (fsc *FsClient) Remove(name string) error {
	db.DPrintf("Remove %v\n", name)
	fid, err := fsc.walkMany(np.Split(name), false)
	if err != nil {
		return err
	}
	err = fsc.npch(fid).Remove(fid)
	return err
}

func (fsc *FsClient) Stat(name string) (*np.Stat, error) {
	db.DPrintf("Stat %v\n", name)
	fid, err := fsc.walkMany(np.Split(name), true)
	if err != nil {
		return nil, err
	}
	reply, err := fsc.npch(fid).Stat(fid)
	if err != nil {
		return nil, err
	}
	return &reply.Stat, nil
}

// XXX clone fid?
func (fsc *FsClient) Readlink(fid np.Tfid) (string, error) {
	_, err := fsc.npch(fid).Open(fid, np.OREAD)
	if err != nil {
		return "", err
	}
	reply, err := fsc.npch(fid).Read(fid, 0, 1024)
	if err != nil {
		return "", err
	}
	// XXX close fid
	return string(reply.Data), nil
}

func (fsc *FsClient) Open(path string, mode np.Tmode) (int, error) {
	db.DPrintf("Open %v %v\n", path, mode)
	fid, err := fsc.walkMany(np.Split(path), true)
	if err != nil {
		return -1, err
	}
	_, err = fsc.npch(fid).Open(fid, mode)
	if err != nil {
		return -1, err
	}
	// XXX check reply.Qid?
	fd := fsc.findfd(fid)
	return fd, nil

}

func (fsc *FsClient) OpenAt(dfd int, name string, mode np.Tmode) (int, error) {
	db.DPrintf("OpenAt %v %v %v\n", dfd, name, mode)

	fid, err := fsc.lookup(dfd)
	if err != nil {
		return -1, err
	}

	fid1, err := fsc.clone(fid)
	if err != nil {
		return -1, err
	}

	n := []string{name}
	reply, err := fsc.npch(fid).Walk(fid, fid1, n)
	if err != nil {
		return -1, err
	}
	fsc.fids[fid1].addn(reply.Qids, n)

	_, err = fsc.npch(fid1).Open(fid1, mode)
	if err != nil {
		return -1, err
	}
	// XXX check reply.Qid?
	fd := fsc.findfd(fid1)
	return fd, nil

}

func (fsc *FsClient) Opendir(path string) (int, error) {
	db.DPrintf("Opendir %v", path)
	return fsc.Open(path, np.OREAD)
}

func (fsc *FsClient) Read(fd int, cnt np.Tsize) ([]byte, error) {
	fdst, err := fsc.lookupSt(fd)
	if err != nil {
		return nil, err
	}
	reply, err := fsc.npch(fdst.fid).Read(fdst.fid, fdst.offset, cnt)
	if err != nil {
		return nil, err
	}
	fdst.offset += np.Toffset(len(reply.Data))
	return reply.Data, err
}

func (fsc *FsClient) Readdir(fd int, n np.Tsize) ([]np.Stat, error) {
	data, err := fsc.Read(fd, n)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, io.EOF
	}
	dirents := []np.Stat{}
	for len(data) > 0 {
		st := np.Stat{}
		err = npcodec.Unmarshal(data, &st)
		if err != nil {
			return dirents, err
		}
		dirents = append(dirents, st)
		sz := np.Tsize(npcodec.SizeNp(st))
		data = data[sz:]
	}
	return dirents, err
}

func (fsc *FsClient) Write(fd int, data []byte) (np.Tsize, error) {
	fdst, err := fsc.lookupSt(fd)
	if err != nil {
		return 0, err
	}
	reply, err := fsc.npch(fdst.fid).Write(fdst.fid, fdst.offset, data)
	if err != nil {
		return 0, err
	}
	fdst.offset += np.Toffset(reply.Count)
	return reply.Count, err
}

func (fsc *FsClient) Lsof() []string {
	var fids []string
	for _, fdst := range fsc.fds {
		if fdst.fid != np.NoFid {
			// collect info about fid...
			//b, err := json.Marshal(fid)
			//if err != nil {
			//	log.Fatal("Marshall error:", err)
			//}
			//fids = append(fids, string(b))
		}
	}
	return fids
}
