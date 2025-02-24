package memfs

import (
	"sigmaos/fs"
	"sigmaos/inode"
	"sigmaos/serr"
	sp "sigmaos/sigmap"
)

func MakeInode(ctx fs.CtxI, p sp.Tperm, m sp.Tmode, parent fs.Dir, mk fs.MakeDirF) (fs.Inode, *serr.Err) {
	i := inode.MakeInode(ctx, p, parent)
	if p.IsDir() {
		return mk(i, MakeInode), nil
	} else if p.IsSymlink() {
		return MakeFile(i), nil
	} else if p.IsPipe() {
		return MakePipe(ctx, i), nil
	} else if p.IsFile() || p.IsEphemeral() {
		return MakeFile(i), nil
	} else {
		return nil, serr.MkErr(serr.TErrInval, p)
	}
}
