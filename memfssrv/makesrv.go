package memfssrv

import (
	"sigmaos/ctx"
	db "sigmaos/debug"
	"sigmaos/dir"
	"sigmaos/fs"
	"sigmaos/fslibsrv"
	"sigmaos/memfs"
	"sigmaos/portclnt"
	"sigmaos/proc"
	"sigmaos/sigmaclnt"
	sp "sigmaos/sigmap"
)

// Make an MemFs and advertise it at pn
func MakeMemFs(pn string, uname sp.Tuname) (*MemFs, error) {
	return MakeMemFsPort(pn, ":0", uname)
}

// Make an MemFs for a specific port and advertise it at pn
func MakeMemFsPort(pn, port string, uname sp.Tuname) (*MemFs, error) {
	sc, err := sigmaclnt.MkSigmaClnt(uname)
	if err != nil {
		return nil, err
	}
	db.DPrintf(db.PORT, "MakeMemFsPort %v %v\n", pn, port)
	fs, err := MakeMemFsPortClnt(pn, port, sc)
	return fs, err
}

// Make an MemFs for a specific port and client, and advertise it at
// pn
func MakeMemFsPortClnt(pn, port string, sc *sigmaclnt.SigmaClnt) (*MemFs, error) {
	return MakeMemFsPortClntFence(pn, port, sc, nil)
}

func MakeMemFsPortClntFence(pn, port string, sc *sigmaclnt.SigmaClnt, fencefs fs.Dir) (*MemFs, error) {
	ctx := ctx.MkCtx("", 0, sp.NoClntId, nil, fencefs, "")
	root := dir.MkRootDir(ctx, memfs.MakeInode, nil)

	uname := sc.Uname()
	srv, err := fslibsrv.MakeSrv(root, pn, port, sc, fencefs, uname)
	if err != nil {
		return nil, err
	}
	mfs := MakeMemFsSrv(sc.Uname(), pn, srv, sc, nil, sc.Uuid())
	return mfs, nil
}

// Allocate server with public port and advertise it
func MakeMemFsPublic(pn string, uname sp.Tuname) (*MemFs, error) {
	sc, err := sigmaclnt.MkSigmaClnt(uname)
	if err != nil {
		return nil, err
	}
	pc, pi, err := portclnt.MkPortClntPort(sc.FsLib)
	if err != nil {
		return nil, err
	}
	// Make server without advertising mnt
	mfs, err := MakeMemFsPortClnt("", ":"+pi.Pb.RealmPort.String(), sc)
	if err != nil {
		return nil, err
	}
	mfs.pc = pc

	if err = pc.AdvertisePort(pn, pi, proc.GetNet(), mfs.MyAddr()); err != nil {
		return nil, err
	}
	return mfs, err
}
