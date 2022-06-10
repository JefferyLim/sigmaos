package resource

import (
	"encoding/json"
	"fmt"

	db "ulambda/debug"
)

type ResourceGrantHandler func(*ResourceMsg)
type ResourceRequestHandler func(*ResourceMsg)

type ResourceMsg struct {
	MsgType      Tmsg
	ResourceType Tresource
	Name         string
	Amount       int
}

func MakeResourceMsg(mt Tmsg, rt Tresource, n string, a int) *ResourceMsg {
	return &ResourceMsg{mt, rt, n, a}
}

func (r *ResourceMsg) Marshal() []byte {
	b, err := json.Marshal(r)
	if err != nil {
		db.DFatalf("Marshal: %v", err)
	}
	return b
}

func (r *ResourceMsg) Unmarshal(b []byte) {
	if err := json.Unmarshal(b, r); err != nil {
		db.DFatalf("Unmarshal: %v", err)
	}
}

func (r *ResourceMsg) String() string {
	return fmt.Sprintf("&{ MsgType: %v ResourceType:%v Name:%v Amount:%v }", r.MsgType, r.ResourceType, r.Name, r.Amount)
}
