package npcodec

import (
	"bufio"
	"io"

	db "sigmaos/debug"
	"sigmaos/sessp"
	"sigmaos/frame"
)

func MarshalFrame(fcm *sessp.FcallMsg, bwr *bufio.Writer) *sessp.Err {
	sp2NpMsg(fcm)
	fc9P := to9P(fcm)
	db.DPrintf(db.NPCODEC, "MarshalFrame %v\n", fc9P)
	f, error := marshal1(false, fc9P)
	if error != nil {
		return sessp.MkErr(sessp.TErrBadFcall, error.Error())
	}
	if err := frame.WriteFrame(bwr, f); err != nil {
		return err
	}
	if error := bwr.Flush(); error != nil {
		db.DPrintf(db.NPCODEC, "flush %v err %v", fcm, error)
		return sessp.MkErr(sessp.TErrBadFcall, error.Error())
	}
	return nil
}

func UnmarshalFrame(rdr io.Reader) (*sessp.FcallMsg, *sessp.Err) {
	f, err := frame.ReadFrame(rdr)
	if err != nil {
		db.DPrintf(db.NPCODEC, "ReadFrame err %v\n", err)
		return nil, err
	}
	fc9p := &Fcall9P{}
	if err := unmarshal(f, fc9p); err != nil {
		db.DPrintf(db.NPCODEC, "unmarshal err %v\n", err)
		return nil, sessp.MkErr(sessp.TErrBadFcall, err)
	}
	fc := toSP(fc9p)
	np2SpMsg(fc)
	return fc, nil
}
