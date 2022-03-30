package fences1

import (
	"encoding/json"
	"log"
	"sync"

	db "ulambda/debug"
	"ulambda/fs"
	"ulambda/inode"
	np "ulambda/ninep"
)

//
// Map of fences indexed by pathname of fence at server.  Use by fssrv
// to keep track of the most recent fence seen.
//

type Epoch struct {
	sync.Mutex
	inode.Inode
	epoch np.Tepoch
}

// XXX how to get a Tpath for inode?
func MakeEpoch(epoch np.Tepoch, parent fs.Dir) *Epoch {
	e := &Epoch{}
	e.epoch = epoch
	e.Inode.SetParent(parent)
	return e
}

// XXX how to get a Tpath for inode?
type FenceTable struct {
	inode.Inode // XXX make type DIR
	sync.Mutex
	fences map[np.Tpath]*Epoch
}

func MakeFenceTable() *FenceTable {
	ft := &FenceTable{}
	ft.fences = make(map[np.Tpath]*Epoch)
	return ft
}

// If new is NoFence, return. If no fence exists for this fence id,
// store it as most recent fence.  If the fence exists but newer,
// update the fence.  If the fence is stale, return error.  If fence
// id exists, return the locked epoch for the fencid so that no one
// can update the fence until this fenced operation has completed.
//
// XXX use read/write mutex and downgrade from Lock to Rlock, since epoch updates
// are rare and we would like to run ops in parallel.
//
// XXX check that clnt is allowed to update fence
func (ft *FenceTable) CheckFence(new np.Tfence1) (*Epoch, *np.Err) {
	ft.Lock()
	defer ft.Unlock()

	if new.FenceId.Path == 0 {
		return nil, nil
	}
	p := new.FenceId.Path
	if e, ok := ft.fences[p]; ok {
		e.Lock()
		if new.Epoch < e.epoch {
			db.DPrintf("FENCES_ERR", "Stale fence %v\n", new)
			e.Unlock()
			return nil, np.MkErr(np.TErrStale, new)
		}
		if new.Epoch > e.epoch {
			db.DPrintf("FENCES", "fenceFcall %v new epoch %v\n", new)
			e.epoch = new.Epoch
		}
		return e, nil
	} else {
		db.DPrintf("FENCES", "fenceFcall %v new fence %v\n", new)
		e := MakeEpoch(new.Epoch, ft)
		e.Lock()
		ft.fences[p] = e
		return e, nil
	}
}

func (ft *FenceTable) Snapshot() []byte {
	b, err := json.Marshal(ft.fences)
	if err != nil {
		db.DFatalf("FATAL Error snapshot encoding fence table: %v", err)
	}
	return b
}

func RestoreRecentTable(b []byte) *FenceTable {
	ft := &FenceTable{}
	err := json.Unmarshal(b, &ft.fences)
	if err != nil {
		db.DFatalf("FATAL error unmarshal fences in restore: %v", err)
	}
	return ft
}
