package fsux

import (
	"os"
	"syscall"

	db "sigmaos/debug"
	"sigmaos/sessp"
	"sigmaos/file"
	"sigmaos/fs"
	"sigmaos/path"
	sp "sigmaos/sigmap"
)

type Symlink struct {
	*Obj
	*file.File
}

func makeSymlink(path path.Path, iscreate bool) (*Symlink, *sessp.Err) {
	s := &Symlink{}
	o, err := makeObj(path)
	if err == nil && iscreate {
		return nil, sessp.MkErr(sessp.TErrExists, path)
	}
	s.Obj = o
	s.File = file.MakeFile()
	return s, nil
}

func (s *Symlink) Open(ctx fs.CtxI, m sp.Tmode) (fs.FsObj, *sessp.Err) {
	db.DPrintf(db.UX, "%v: SymOpen %v m %x\n", ctx, s, m)
	if m&sp.OWRITE == sp.OWRITE {
		// no calls to update target of an existing symlink,
		// so remove it.  close() will make the symlink with
		// the new target.
		os.Remove(s.Obj.pathName.String())
	}
	if m&0x1 == sp.OREAD {
		// read the target and write it to the in-memory file,
		// so that Read() can read it.
		target, error := os.Readlink(s.Obj.pathName.String())
		if error != nil {
			return nil, UxTo9PError(error, s.Obj.pathName.Base())
		}
		db.DPrintf(db.UX, "Readlink target='%s'\n", target)
		d := []byte(target)
		_, err := s.File.Write(ctx, 0, d, sp.NoV)
		if err != nil {
			db.DPrintf(db.UX, "Write %v err %v\n", s, err)
			return nil, err
		}
	}
	return nil, nil
}

func (s *Symlink) Close(ctx fs.CtxI, mode sp.Tmode) *sessp.Err {
	db.DPrintf(db.UX, "%v: SymClose %v %x\n", ctx, s, mode)
	if mode&sp.OWRITE == sp.OWRITE {
		d, err := s.File.Read(ctx, 0, sp.MAXGETSET, sp.NoV)
		if err != nil {
			return err
		}
		error := syscall.Symlink(string(d), s.Obj.pathName.String())
		if error != nil {
			db.DPrintf(db.UX, "symlink %s err %v\n", s, error)
			UxTo9PError(error, s.Obj.pathName.Base())
		}
	}
	return nil
}
