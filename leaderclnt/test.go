package leaderclnt

import (
	"strconv"
	"time"

	"github.com/stretchr/testify/assert"

	db "sigmaos/debug"
	"sigmaos/fslib"
	"sigmaos/serr"
	sp "sigmaos/sigmap"
	"sigmaos/test"
)

//
// For testing
//

const (
	leadername = "name/leader"
)

func OldleaderTest(ts *test.Tstate, pn string, crash bool) *LeaderClnt {
	ts.MkDir(pn, 0777)
	ts.Remove(pn + "/f")
	ts.Remove(pn + "/g")

	ch := make(chan bool)
	go func() {
		fsl2, err := fslib.MakeFsLibAddr("leader", sp.ROOTREALM, ts.GetLocalIP(), ts.NamedAddr())
		assert.Nil(ts.T, err, "MakeFsLib")

		l, err := MakeLeaderClnt(fsl2, leadername, 0777)
		assert.Nil(ts.T, err)
		err = l.LeadAndFence(nil, []string{pn})
		assert.Nil(ts.T, err, "BecomeLeaderEpoch")

		fd, err := fsl2.Create(pn+"/f", 0777, sp.OWRITE)
		assert.Nil(ts.T, err, "Create")

		ch <- true

		db.DPrintf(db.TEST, "sign off as leader..\n")

		l.ReleaseLeadership()

		time.Sleep(1 * time.Second)

		db.DPrintf(db.TEST, "Try to write..\n")

		// A thread shouldn't write after resigning, but this thread
		// lost leader status, and the other thread should have it by
		// now so this write to pn should fail, because it is fenced
		// with the fsl's fence, which is the old leader's one.

		_, err = fsl2.PutFile(pn+"/f", 0777, sp.OWRITE, []byte(strconv.Itoa(0)))
		assert.NotNil(ts.T, err, "Put")
		db.DPrintf(db.TEST, "Put err %v\n", err)
		assert.True(ts.T, serr.IsErrCode(err, serr.TErrStale))

		fsl2.Close(fd)

		ch <- true
	}()

	// Wait until other thread is leader
	<-ch

	db.DPrintf(db.TEST, "Become leader..\n")

	l, err := MakeLeaderClnt(ts.FsLib, leadername, 0777)
	assert.Nil(ts.T, err)
	// When other thread resigns, we become leader and start new epoch
	err = l.LeadAndFence(nil, []string{pn})
	assert.Nil(ts.T, err, "BecomeLeaderEpoch")

	// Do some op so that server becomes aware of new epoch
	_, err = ts.PutFile(pn+"/g", 0777, sp.OWRITE, []byte(strconv.Itoa(0)))
	assert.Nil(ts.T, err, "PutFile")

	if crash {
		db.DPrintf(db.TEST, "kill named..\n")
		err := ts.KillOne(sp.NAMEDREL)
		assert.Nil(ts.T, err)
	}

	db.DPrintf(db.TEST, "Let old leader run..\n")

	<-ch

	fd, err := ts.Open(pn+"/f", sp.OREAD)
	assert.Nil(ts.T, err, "Open")
	b, err := ts.Read(fd, 100)
	assert.Equal(ts.T, 0, len(b))

	return l
}
