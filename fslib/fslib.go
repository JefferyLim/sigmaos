package fslib

import (
	db "sigmaos/debug"
	"sigmaos/fdclnt"
	"sigmaos/proc"
	sp "sigmaos/sigmap"
    "sigmaos/authclnt"
)

type FsLib struct {
	*fdclnt.FdClient
	namedAddr sp.Taddrs
}

func MakeFsLibAddrNet(uname sp.Tuname, realm sp.Trealm, lip string, addrs sp.Taddrs, clntnet string) (*FsLib, error) {
	db.DPrintf(db.PORT, "MakeFsLibAddrRealm: uname %s lip %s addrs %v uuid %v\n", uname, lip, addrs, proc.GetUuid())
        
    db.DPrintf(db.JEFF, "procdir: %v", proc.GetProcDir())
    db.DPrintf(db.JEFF, "parentdir: %v", proc.GetParentDir())
	
    // Check for an inherited UUID
    var uuid string
    var err error
    uuid = proc.GetUuid()

	if proc.GetIsPrivilegedProc() == true || string(uname) == "kernel" {
		// temporary solution of establishing a privileged uuid
		uuid = "priv"
	} else {
		// non-privileged procs must obtain a uuid through the authclnt
		if uuid  == "" {
			uuid, err = authclnt.Auth(string(uname))

			if err == nil {
				// set the uuid as an environment variable
				// this is to make passing uuid to children easier
				// ideally, one would pass it as a variable
				proc.SetUuid(string(uuid))
			}else{
                
                db.DPrintf(db.JEFF, "wtf: %v, err %v", uuid, err)
                return nil, err
            }
		}
	}

    db.DPrintf(db.JEFF, "uuid: %v", uuid)

    fl := &FsLib{
		FdClient:  fdclnt.MakeFdClient(nil, uname, clntnet, realm, lip, sp.Tsize(10_000_000), sp.Tuuid(uuid)),
		namedAddr: addrs,
	}

	return fl, nil
}

func MakeFsLibAddr(uname sp.Tuname, realm sp.Trealm, lip string, addrs sp.Taddrs) (*FsLib, error) {
	return MakeFsLibAddrNet(uname, realm, lip, addrs, proc.GetNet())
}

// Only to be called by procs.
func MakeFsLib(uname sp.Tuname) (*FsLib, error) {
	as, err := proc.Named()
	if err != nil {
		return nil, err
	}
	return MakeFsLibAddr(uname, proc.GetRealm(), proc.GetSigmaLocal(), as)
}

func (fl *FsLib) NamedAddr() sp.Taddrs {
	mnt := fl.GetMntNamed(fl.Uname(), fl.Uuid())
	return mnt.Addr
}

func (fl *FsLib) MountTree(addrs sp.Taddrs, tree, mount string) error {
	return fl.FdClient.MountTree(fl.Uname(), addrs, tree, mount, fl.Uuid())
}

func (fl *FsLib) DetachAll() error {
	return fl.PathClnt.DetachAll()
}
