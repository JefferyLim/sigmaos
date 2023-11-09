package fdclnt

import (
	"fmt"

	db "sigmaos/debug"
	"sigmaos/fidclnt"
	"sigmaos/path"
	"sigmaos/pathclnt"
	"sigmaos/reader"
	"sigmaos/serr"
	sp "sigmaos/sigmap"
	"sigmaos/writer"
    "sigmaos/proc"
    "sigmaos/authclnt"

)

//
// Procs interact with servers using Unix-like file descriptor
// interface and pathnames.
//
// A hypothetical kernel could multiplex multiple procs over one
// FidClnt, which allows a shared TCP connection to a server. A kernel
// could also use fds to share file descriptors state (e.g., offset)
// between parent and child.  Since we have no kernel implementing
// procs, these use cases are speculative.
//
// The FdClient is per user, while a single pathclnt can be shared
// between many FdClients since pathclnt requires a uname being passed
// in. The standard use case is, however, to have one pathclnt per
// FdClient.
//

type FdClient struct {
    *pathclnt.PathClnt
	fds   *FdTable
	uname sp.Tuname // the principal associated with this FdClient
    uuid sp.Tuuid // session uuid
}

func MakeFdClient(fsc *fidclnt.FidClnt, uname sp.Tuname, clntnet string, realm sp.Trealm, lip string, sz sp.Tsize, uuid sp.Tuuid) *FdClient {
	fdc := &FdClient{}
	fdc.PathClnt = pathclnt.MakePathClnt(fsc, clntnet, realm, lip, sz)
	fdc.fds = mkFdTable()
	fdc.uname = uname
    
    if proc.GetIsPrivilegedProc() == true || string(uname) == "kernel" {
        fdc.uuid = sp.Tuuid(string("priv"))
    }else{
        if string(uuid) == "" {
            uuid, err := authclnt.Auth(string(uname))
            if err == nil {
                fdc.uuid = sp.Tuuid(uuid)
                db.DPrintf(db.JEFF, "fdclnt/fdclnt.go UUID: %v", uuid)
                proc.SetUuid(string(uuid))
            }
        }else{
            fdc.uuid = uuid
        }

        // An empty uuid is not acceptable at this point, so we should probably create an error here 
    }
	
    return fdc
}

func (fdc *FdClient) String() string {
	str := fmt.Sprintf("Table:\n")
	str += fmt.Sprintf("fds %v\n", fdc.fds)
	str += fmt.Sprintf("fsc %v\n", fdc.PathClnt)
	return str
}

func (fdc *FdClient) Uuid() sp.Tuuid {
    return fdc.uuid
}


func (fdc *FdClient) Uname() sp.Tuname {
	return fdc.uname
}

func (fdc *FdClient) Close(fd int) error {
	fid, error := fdc.fds.lookup(fd)
	if error != nil {
		return error
	}
	err := fdc.PathClnt.Clunk(fid)
	if err != nil {
		return err
	}
	return nil
}

func (fdc *FdClient) Qid(fd int) (*sp.Tqid, error) {
	fid, error := fdc.fds.lookup(fd)
	if error != nil {
		return nil, error
	}
	return fdc.PathClnt.Qid(fid), nil
}

func (fdc *FdClient) Stat(name string) (*sp.Stat, error) {
	return fdc.PathClnt.Stat(name, fdc.uname, fdc.uuid)
}

func (fdc *FdClient) Create(path string, perm sp.Tperm, mode sp.Tmode) (int, error) {
	fid, err := fdc.PathClnt.Create(path, fdc.uname, perm, mode, sp.NoLeaseId, sp.NoFence(), fdc.uuid)
	if err != nil {
		return -1, err
	}
	fd := fdc.fds.allocFd(fid, mode)
	return fd, nil
}

func (fdc *FdClient) CreateEphemeral(path string, perm sp.Tperm, mode sp.Tmode, lid sp.TleaseId, f sp.Tfence) (int, error) {
	fid, err := fdc.PathClnt.Create(path, fdc.uname, perm|sp.DMTMP, mode, lid, f, fdc.uuid)
	if err != nil {
		return -1, err
	}
	fd := fdc.fds.allocFd(fid, mode)
	return fd, nil
}

func (fdc *FdClient) OpenWatch(path string, mode sp.Tmode, w pathclnt.Watch) (int, error) {
	fid, err := fdc.PathClnt.OpenWatch(path, fdc.uname, mode, w, fdc.uuid)
	if err != nil {
		return -1, err
	}
	fd := fdc.fds.allocFd(fid, mode)
	return fd, nil
}

func (fdc *FdClient) Open(path string, mode sp.Tmode) (int, error) {
	return fdc.OpenWatch(path, mode, nil)
}

func (fdc *FdClient) CreateOpen(path string, perm sp.Tperm, mode sp.Tmode) (int, error) {
	fd, err := fdc.Create(path, perm, mode)
	if err != nil && !serr.IsErrCode(err, serr.TErrExists) {
		db.DPrintf(db.FDCLNT_ERR, "Create %v err %v", path, err)
		return -1, err
	}
	if err != nil {
		fd, err = fdc.Open(path, mode)
		if err != nil {
			db.DPrintf(db.FDCLNT_ERR, "Open %v err %v", path, err)
			return -1, err
		}
	}
	return fd, nil
}

func (fdc *FdClient) SetRemoveWatch(pn string, w pathclnt.Watch) error {
	return fdc.PathClnt.SetRemoveWatch(pn, fdc.uname, w, fdc.uuid)
}

func (fdc *FdClient) Rename(old, new string) error {
	return fdc.PathClnt.Rename(old, new, fdc.uname, fdc.uuid)
}

func (fdc *FdClient) Remove(pn string) error {
	return fdc.PathClnt.Remove(pn, fdc.uname, fdc.uuid)
}

func (fdc *FdClient) GetFile(fname string) ([]byte, error) {
	return fdc.PathClnt.GetFile(fname, fdc.uname, sp.OREAD, 0, sp.MAXGETSET, fdc.uuid)
}

func (fdc *FdClient) PutFile(fname string, perm sp.Tperm, mode sp.Tmode, data []byte, off sp.Toffset, lid sp.TleaseId) (sp.Tsize, error) {
	return fdc.PathClnt.PutFile(fname, fdc.uname, mode|sp.OWRITE, perm, data, off, lid, fdc.uuid)
}

func (fdc *FdClient) MakeReader(fd int, path string, chunksz sp.Tsize) *reader.Reader {
	fid, err := fdc.fds.lookup(fd)
	if err != nil {
		return nil
	}
	return fdc.PathClnt.MakeReader(fid, path, chunksz)
}

func (fdc *FdClient) MakeWriter(fd int) *writer.Writer {
	fid, err := fdc.fds.lookup(fd)
	if err != nil {
		return nil
	}
	return fdc.PathClnt.MakeWriter(fid)
}

func (fdc *FdClient) readFid(fd int, fid sp.Tfid, off sp.Toffset, cnt sp.Tsize) ([]byte, error) {
	data, err := fdc.PathClnt.ReadF(fid, off, cnt)
	if err != nil {
		return nil, err
	}
	fdc.fds.incOff(fd, sp.Toffset(len(data)))
	return data, nil
}

func (fdc *FdClient) Read(fd int, cnt sp.Tsize) ([]byte, error) {
	fid, off, error := fdc.fds.lookupOff(fd)
	if error != nil {
		return nil, error
	}
	return fdc.readFid(fd, fid, off, cnt)
}

func (fdc *FdClient) writeFid(fd int, fid sp.Tfid, off sp.Toffset, data []byte, f sp.Tfence) (sp.Tsize, error) {
	sz, err := fdc.PathClnt.WriteF(fid, off, data, f)
	if err != nil {
		return 0, err
	}
	fdc.fds.incOff(fd, sp.Toffset(sz))
	return sz, nil
}

func (fdc *FdClient) Write(fd int, data []byte) (sp.Tsize, error) {
	fid, off, error := fdc.fds.lookupOff(fd)
	if error != nil {
		return 0, error
	}
	return fdc.writeFid(fd, fid, off, data, sp.NoFence())
}

func (fdc *FdClient) WriteFence(fd int, data []byte, f sp.Tfence) (sp.Tsize, error) {
	fid, off, error := fdc.fds.lookupOff(fd)
	if error != nil {
		return 0, error
	}
	return fdc.writeFid(fd, fid, off, data, f)
}

func (fdc *FdClient) WriteRead(fd int, data []byte) ([]byte, error) {
	fid, _, error := fdc.fds.lookupOff(fd)
	if error != nil {
		return nil, error
	}
	b, err := fdc.PathClnt.WriteRead(fid, data)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (fdc *FdClient) Seek(fd int, off sp.Toffset) error {
	err := fdc.fds.setOffset(fd, off)
	if err != nil {
		return err
	}
	return nil
}

func (fdc *FdClient) PathLastSymlink(pn string) (path.Path, path.Path, error) {
	return fdc.PathClnt.PathLastSymlink(pn, fdc.uname, fdc.uuid)
}
