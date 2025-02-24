package test

import (
	db "sigmaos/debug"
	"sigmaos/sigmaclnt"
	sp "sigmaos/sigmap"
)

// Tstate relative to a realm.
type RealmTstate struct {
	realm sp.Trealm
	*sigmaclnt.SigmaClnt
	Ts *Tstate
}

// Creates a realm, and a tstate relative to that realm.
func MakeRealmTstate(ts *Tstate, realm sp.Trealm) *RealmTstate {
	return makeRealmTstateClnt(ts, realm, true)
}

// Makes a tstate relative to an existing realm.
func MakeRealmTstateClnt(ts *Tstate, realm sp.Trealm) *RealmTstate {
	return makeRealmTstateClnt(ts, realm, false)
}

func makeRealmTstateClnt(ts *Tstate, realm sp.Trealm, makerealm bool) *RealmTstate {
	if makerealm {
		net := ""
		if Overlays {
			net = realm.String()
		}
		db.DPrintf(db.TEST, "Make realm %v", realm)
		if err := ts.rc.MakeRealm(realm, net); err != nil {
			db.DFatalf("Error MakeRealmTstate MkRealm: %v", err)
		}
		db.DPrintf(db.TEST, "Done making realm %v", realm)
	}
	if sc, err := sigmaclnt.MkSigmaClntRealm(ts.FsLib, "test", realm); err != nil {
		db.DFatalf("Error MakeRealmTstate MkSigmaClnt: %v", err)
	} else {
		return &RealmTstate{
			realm:     realm,
			SigmaClnt: sc,
			Ts:        ts,
		}
	}
	return nil
}

func (rts *RealmTstate) GetRealm() sp.Trealm {
	return rts.realm
}

func (rts *RealmTstate) Remove() error {
	return rts.Ts.rc.RemoveRealm(rts.realm)
}
