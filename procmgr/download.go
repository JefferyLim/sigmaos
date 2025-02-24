package procmgr

import (
	"fmt"
	"path"
	"time"

	db "sigmaos/debug"
	"sigmaos/proc"
	"sigmaos/rand"
	"sigmaos/serr"
	sp "sigmaos/sigmap"
)

const (
	N_DOWNLOAD_RETRIES = 100
)

// ProcMgr caches binary locally. There is a cache directory for each realm.
func cachePath(realm sp.Trealm, prog string) string {
	return path.Join(sp.UXBIN, "user", "realms", realm.String(), prog)
}

func (mgr *ProcMgr) setupUserBinCache(p *proc.Proc) {
	// Only set up cache dir when we start spawning user procs. By this time, UX
	// will already be up.
	if p.Privileged {
		return
	}

	mgr.Lock()
	defer mgr.Unlock()

	if _, ok := mgr.cachedirs[p.GetRealm()]; !ok {
		cachePn := path.Dir(cachePath(p.GetRealm(), p.Program))
		// Make a dir to cache the realm's binaries.
		if err := mgr.rootsc.MkDir(cachePn, 0777); err != nil && !serr.IsErrCode(err, serr.TErrExists) {
			db.DFatalf("Error MkDir cache dir [%v]: %v", cachePn, err)
		}
		mgr.cachedirs[proc.GetRealm()] = true
	}
}

// Returns true if the proc is already cached.
// XXX check timestamps/versions?
func (mgr *ProcMgr) alreadyCached(realm sp.Trealm, prog string) bool {
	cachePn := cachePath(realm, prog)
	_, err := mgr.rootsc.Stat(cachePn)
	if err != nil {
		db.DPrintf(db.PROCMGR, "uxp %v err %v\n", cachePn, err)
		return false
	}
	return true
}

func (mgr *ProcMgr) downloadProc(p *proc.Proc) {
	// Privileged procs' bins should be part of the base image.
	if p.IsPrivilegedProc() {
		return
	}
	// Download the bin from s3, if it isn't already cached locally.
	if err := mgr.downloadProcBin(p); err != nil {
		db.DFatalf("failed to download proc err:%v proc:%v", err, p)
	}
}

// Lock to ensure the bin is downloaded only once, even if multiple copies of
// the proc are starting up on the same schedd.
func (mgr *ProcMgr) downloadProcBin(p *proc.Proc) error {
	mgr.Lock()
	defer mgr.Unlock()

	// If already cached, return immediately.
	if mgr.alreadyCached(p.GetRealm(), p.Program) {
		return nil
	}
	commonBins := path.Join(sp.UXBIN, "user", "common")
	// Search order:
	// 1. Try to copy from the local bin cache (user bins will be here when built locally).
	// 2. Try the shared to download from the realm's s3 bucket.
	// 3. Try the global version repo.
	paths := []string{
		commonBins,
		path.Join(sp.S3, "~local", p.GetRealm().String(), "/bin"),
		path.Join(sp.S3, "~local", mgr.bintag, "/bin"),
	}
	var err error
	for _, pp := range paths {
		db.DPrintf(db.ALWAYS, "Download bintag %v sigmatag %v pp %v prog %v", mgr.bintag, proc.GetBuildTag(), pp, p.Program)
		if e := mgr.downloadProcPath(p.GetRealm(), pp, p.Program); e == nil {
			return nil
		} else {
			err = e
		}
	}
	return err
}

func (mgr *ProcMgr) downloadProcPath(realm sp.Trealm, from, prog string) error {
	// May need to retry if ux crashes.
	var i int
	var err error
	for i = 0; i < N_DOWNLOAD_RETRIES; i++ {
		// Return if successful. Else, retry
		if err = mgr.tryDownloadProcPath(realm, from, prog); err == nil {
			return nil
		} else {
			db.DPrintf(db.PROCMGR_ERR, "Error tryDownloadProcBin [%v]: %v", path.Join(from, prog), err)
			if serr.IsErrCode(err, serr.TErrNotfound) {
				break
			}
		}
	}
	return fmt.Errorf("downloadProcPath: Couldn't download %v in %v retries err %v", path.Join(from, prog), i, err)
}

// Try to download a proc at pn to local Ux dir. May fail if ux crashes.
func (mgr *ProcMgr) tryDownloadProcPath(realm sp.Trealm, from, prog string) error {
	src := path.Join(from, prog)
	start := time.Now()
	db.DPrintf(db.PROCMGR, "tryDownloadProcPath %s", src)
	cachePn := cachePath(realm, prog)
	// Copy the binary from s3 to a temporary file.
	tmppath := path.Join(cachePn + "-tmp-" + rand.String(8))
	if err := mgr.rootsc.CopyFile(src, tmppath); err != nil {
		return err
	}
	// Rename the temporary file.
	if err := mgr.rootsc.Rename(tmppath, cachePn); err != nil {
		// If another schedd (or another thread on this schedd) already completed the
		// download, then we consider the download successful. Any other error
		// (e.g. ux crashed) is unexpected.
		if err != nil && !serr.IsErrCode(err, serr.TErrExists) {
			return err
		}
		// If someone else completed the download before us, remove the temp file.
		mgr.rootsc.Remove(tmppath)
	}
	db.DPrintf(db.PROCMGR, "Took %v to download proc %v", time.Since(start), src)
	return nil
}
