package dir

import (
	"encoding/json"
	"log"

	"ulambda/fs"
	"ulambda/inode"
)

type DirSnapshot struct {
	InodeSnap []byte
	Entries   map[string]uint64
}

func makeDirSnapshot(fn fs.SnapshotF, d *DirImpl) []byte {
	ds := &DirSnapshot{}
	ds.InodeSnap = d.FsObj.Snapshot(fn)
	ds.Entries = make(map[string]uint64)
	for n, e := range d.entries {
		if n == "." {
			continue
		}
		ds.Entries[n] = fn(e)
	}
	b, err := json.Marshal(ds)
	if err != nil {
		log.Fatalf("FATAL Error snapshot encoding DirImpl: %v", err)
	}
	return b
}

func restore(d *DirImpl, fn fs.RestoreF, b []byte) fs.FsObj {
	ds := &DirSnapshot{}
	err := json.Unmarshal(b, ds)
	if err != nil {
		log.Fatalf("FATAL error unmarshal file in restoreDir: %v", err)
	}
	d.FsObj = inode.RestoreInode(fn, ds.InodeSnap)
	for name, ptr := range ds.Entries {
		d.entries[name] = fn(ptr)
	}
	return d
}
