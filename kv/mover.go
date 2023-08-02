package kv

import (
	"strconv"
	"sync"
	"time"

	"sigmaos/crash"
	db "sigmaos/debug"
	"sigmaos/fslib"
	"sigmaos/proc"
	"sigmaos/serr"
	"sigmaos/sigmaclnt"
	sp "sigmaos/sigmap"
)

//
// Move shards between servers
//

type Mover struct {
	mu sync.Mutex
	*sigmaclnt.SigmaClnt
	job   string
	fence *sp.Tfence
	shard uint32
	cc    *CacheClnt
	exit  bool
}

func checkFence(fsl *fslib.FsLib, job string, fence *sp.Tfence) {
	config := Config{}
	if err := fsl.GetFileJson(KVConfig(job), &config); err != nil {
		db.DPrintf(db.ALWAYS, "checkFence: GetFile err %v\n", err)
	}
	if fence.LessThan(&config.Fence) {
		db.DPrintf(db.ALWAYS, "checkFence: Mover is behind %v %v\n", fence, config.Fence)
	}
}

func MakeMover(job, epochstr, shard, src, dst string) (*Mover, error) {
	sc, err := sigmaclnt.MkSigmaClnt(sp.Tuname("mover-" + proc.GetPid().String()))
	if err != nil {
		return nil, err
	}
	fence, err := sp.NewFenceJson([]byte(epochstr))
	if err != nil {
		return nil, err
	}
	mv := &Mover{fence: fence,
		SigmaClnt: sc,
		job:       job,
		cc:        NewCacheClnt(sc.FsLib, NSHARD),
		exit:      true,
	}
	if sh, err := strconv.ParseUint(shard, 10, 32); err != nil {
		return nil, err
	} else {
		mv.shard = uint32(sh)
	}
	if err := mv.Started(); err != nil {
		db.DFatalf("%v: couldn't start %v\n", proc.GetName(), err)
	}

	// crash.Crasher(mv.FsLib)

	if p := crash.PartitionParentProb(mv.SigmaClnt, 50); p {
		mv.exit = false
		time.Sleep(2 * time.Second)
	}

	checkFence(mv.FsLib, mv.job, mv.fence)

	return mv, nil
}

// Copy shard from src to dst
func (mv *Mover) moveShard(s, d string) error {
	if err := mv.cc.FreezeShard(s, mv.shard, mv.fence); err != nil {
		db.DPrintf(db.KVMV_ERR, "FreezeShard %v err %v\n", s, err)
		// did previous mover finish the job?
		if serr.IsErrCode(err, serr.TErrNotfound) {
			return nil
		}
		return err
	}

	// A crashed mover may have created the shard and partially filled
	// it; remove it and start over.
	if err := mv.cc.DeleteShard(d, mv.shard, mv.fence); err != nil {
		db.DPrintf(db.KVMV_ERR, "DeleteShard %v err %v\n", mv.shard, err)
		if !serr.IsErrCode(err, serr.TErrNotfound) {
			return err
		}
	}

	if err := mv.cc.CreateShard(d, mv.shard, mv.fence); err != nil {
		db.DPrintf(db.KVMV_ERR, "CreateShard %v err %v\n", mv.shard, err)
		return err
	}
	vals, err := mv.cc.DumpShard(s, mv.shard)
	if err != nil {
		db.DPrintf(db.KVMV_ERR, "DumpShard %v err %v\n", mv.shard, err)
		return err
	}
	if err := mv.cc.FillShard(d, mv.shard, vals, mv.fence); err != nil {
		db.DPrintf(db.KVMV_ERR, "FillShard %v err %v\n", mv.shard, err)
		return err
	}

	// Mark that move is done by deleting s
	if err := mv.cc.DeleteShard(s, mv.shard, mv.fence); err != nil {
		db.DPrintf(db.KVMV_ERR, "DeleteShard %v err %v\n", mv.shard, err)
		return err
	}
	return nil
}

func (mv *Mover) Move(src, dst string) {
	db.DPrintf(db.KVMV, "conf %v: mv %d from %v to %v\n", mv.fence, mv.shard, src, dst)
	err := mv.moveShard(src, dst)
	if err != nil {
		db.DPrintf(db.KVMV_ERR, "conf %v: mv %d from %v to %v err %v\n", mv.fence, mv.shard, src, dst, err)
	}
	db.DPrintf(db.KVMV, "conf %v: mv %d  done from %v to %v err %v\n", mv.fence, mv.shard, src, dst, err)
	if mv.exit {
		if err != nil {
			mv.ClntExit(proc.MakeStatusErr(err.Error(), nil))
		} else {
			mv.ClntExitOK()
		}
	}
}
