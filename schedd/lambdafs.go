package schedd

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"time"
	"unicode"
	"unicode/utf8"

	db "ulambda/debug"
	np "ulambda/ninep"
	npo "ulambda/npobjsrv"
)

//
// File system interface to lambdas. A lambda is a directory and its
// fields are files.  An object represents either one of them.
//
type Obj struct {
	name   []string
	t      np.Tperm
	parent npo.NpObj
	sd     *Sched
	l      *Lambda
	time   int64
}

func (sd *Sched) MakeObj(path []string, t np.Tperm, p npo.NpObj) npo.NpObj {
	o := &Obj{path, t, p, sd, nil, int64(0)}
	return o
}

func (o *Obj) Perm() np.Tperm {
	return o.t
}

func (o *Obj) Size() np.Tlength {
	return 0
}

func (o *Obj) Version() np.TQversion {
	return 0
}

func (o *Obj) Qid() np.Tqid {
	switch len(o.name) {
	case 0:
		return np.MakeQid(np.Qtype(o.t>>np.QTYPESHIFT),
			np.TQversion(0), np.Tpath(0))
	case 1, 2:
		if o.name[0] == "runq" {
			return np.MakeQid(np.Qtype(o.t>>np.QTYPESHIFT),
				np.TQversion(0), np.Tpath(1))
		}
		return np.MakeQid(np.Qtype(o.t>>np.QTYPESHIFT),
			np.TQversion(0), np.Tpath(o.l.uid))
	default:
		log.Fatalf("Qid %v\n", o)
	}
	return np.Tqid{}
}

func (o *Obj) Create(ctx npo.CtxI, name string, perm np.Tperm, m np.Tmode) (npo.NpObj, error) {
	db.DLPrintf("SCHEDD", "%v: Create %v\n", o, name)
	if !o.t.IsDir() {
		return nil, fmt.Errorf("not supported")
	}
	// Creating a lambda is always a directory
	o1 := o.sd.MakeObj(append(o.name, name), perm|np.DMDIR, o).(*Obj)
	o1.time = time.Now().Unix()
	o1.l = makeLambda(o.sd, name, o1)
	return o1, nil
}

// check permissions etc.
func (o *Obj) Open(ctx npo.CtxI, m np.Tmode) error {
	return nil
}

func (o *Obj) Lookup(ctx npo.CtxI, p []string) ([]npo.NpObj, []string, error) {
	db.DLPrintf("SCHEDD", "%v: lookup %v %v %v\n", ctx, o, p, len(p))
	if !o.t.IsDir() {
		return nil, nil, fmt.Errorf("Not a directory")
	}
	// XXX maybe include root dir
	var os []npo.NpObj
	switch len(o.name) {
	case 0:
		if len(p) == 1 && p[0] == "runq" {
			return []npo.NpObj{o.sd.runq}, nil, nil
		}
		l := o.sd.findLambda(p[0])
		if l == nil {
			return nil, nil, fmt.Errorf("not found")
		}
		o1 := l.obj
		if len(p) > 1 {
			o1 = o1.sd.MakeObj(append(o1.name, p[1]), 0, o1).(*Obj)
			o1.time = o.time
			o1.l = l
		}
		os = []npo.NpObj{o1}
	case 1:
		o1 := o.sd.MakeObj(append(o.name, p[0]), 0, o).(*Obj)
		o1.time = o.time
		o1.l = o.l
		os = []npo.NpObj{o1}
	default:
		log.Fatalf("%v: Lookup: %v\n", o, p)
	}
	return os, nil, nil
}

func (o Obj) stat() *np.Stat {
	st := &np.Stat{}
	switch len(o.name) {
	case 0:
		st.Name = ""
	case 1:
		st.Name = o.name[0]
	case 2:
		st.Name = o.name[1]
	default:
		log.Fatalf("stat: name %v\n", o.name)
	}
	st.Mode = np.Tperm(0777) | o.t
	st.Mtime = uint32(o.time)
	st.Qid = o.Qid()
	return st
}

func (o *Obj) readLambda() ([]*np.Stat, error) {
	db.DLPrintf("SCHEDD", "readLambda: %v\n", o)
	st := []*np.Stat{}

	v := reflect.ValueOf(Lambda{})
	for i := 0; i < v.NumField(); i++ {
		n := v.Type().Field(i).Name
		r, _ := utf8.DecodeRuneInString(n)
		if unicode.IsUpper(r) {
			o1 := o.sd.MakeObj(append(o.name, n), 0, o).(*Obj)
			o1.time = o.time
			o1.l = o.l
			st = append(st, o1.stat())
		}
	}
	return st, nil
}

func (sd *Sched) ps() []*np.Stat {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	dir := []*np.Stat{}
	for _, l := range sd.ls {
		dir = append(dir, l.obj.stat())
	}
	return dir
}

func (o *Obj) ReadDir(ctx npo.CtxI, off np.Toffset, cnt np.Tsize, v np.TQversion) ([]*np.Stat, error) {
	db.DLPrintf("SCHEDD", "readDir: %v\n", o)
	switch len(o.name) {
	case 0:
		return o.sd.ps(), nil
	case 1:
		return o.readLambda()
	default:
		log.Fatalf("ReadDir: name %v\n", o)
	}
	return nil, nil
}

func (o *Obj) ReadFile(ctx npo.CtxI, off np.Toffset, cnt np.Tsize, v np.TQversion) ([]byte, error) {
	db.DLPrintf("SCHEDD", "%v: ReadFile: %v %v\n", o, off, cnt)
	if len(o.name) == 1 {
		if off != 0 {
			return nil, nil
		}
		b, err := o.sd.findRunnableLambda()
		db.DLPrintf("SCHEDD", "%v: ReadFile runnableLambda: %v %v\n", o, b, err)
		return b, err
	}
	if len(o.name) != 2 {
		log.Fatalf("ReadFile: name != 2 %v\n", o)
	}
	if off != 0 {
		return nil, nil
	}
	o.l.mu.Lock()
	defer o.l.mu.Unlock()

	var b []byte
	switch o.name[1] {
	case "ExitStatus":
		o.l.waitForL()
		b = []byte(o.l.ExitStatus)
	case "Status":
		b = []byte(o.l.Status)
	case "Program":
		b = []byte(o.l.Program)
	case "Pid":
		b = []byte(o.l.Pid)
	case "Dir":
		b = []byte(o.l.Dir)
	case "Args":
		return json.Marshal(o.l.Args)
	case "Env":
		return json.Marshal(o.l.Env)
	case "ConsDep":
		return json.Marshal(o.l.ConsDep)
	case "ProdDep":
		return json.Marshal(o.l.ProdDep)
	case "ExitDep":
		return json.Marshal(o.l.ExitDep)
	default:
		return nil, fmt.Errorf("Unreadable field %v", o.name[0])
	}
	return b, nil
}

// kill?
func (o *Obj) Remove(ctx npo.CtxI, name string) error {
	return fmt.Errorf("not supported")
}

func (o *Obj) Rename(ctx npo.CtxI, from, to string) error {
	return fmt.Errorf("not supported")
}

func (o *Obj) Stat(ctx npo.CtxI) (*np.Stat, error) {
	return o.stat(), nil
}

func (o *Obj) WriteFile(ctx npo.CtxI, off np.Toffset, data []byte, v np.TQversion) (np.Tsize, error) {
	db.DLPrintf("SCHEDD", "%v: writeFile %v %v\n", o, off, len(data))
	if len(o.name) != 2 {
		log.Fatalf("WriteFile: name != 2 %v\n", o)
	}
	switch o.name[1] {
	case "ExitStatus":
		o.l.writeExitStatus(string(data))
	case "Status":
		o.l.writeStatus(string(data))
	case "ExitDep":
		o.l.swapExitDependency(string(data))
	default:
		return 0, fmt.Errorf("Unwritable field %v", o.name[0])
	}
	return np.Tsize(len(data)), nil
}

func (o *Obj) WriteDir(ctx npo.CtxI, off np.Toffset, data []byte, v np.TQversion) (np.Tsize, error) {
	db.DLPrintf("SCHEDD", "%v: writeDir %v %v\n", o, off, len(data))
	switch len(o.name) {
	case 0:
		return 0, fmt.Errorf("Root is not writable %v", o)
	case 1:
		if o.l.Status == "Init" {
			err := o.l.init(data)
			if err != nil {
				return 0, nil
			}
			o.sd.spawn(o.l)
			return np.Tsize(len(data)), nil
		} else {
			return 0, fmt.Errorf("Lambda already running")
		}
	default:
		log.Fatalf("ReadDir: name %v\n", o)
	}
	return 0, nil
}

func (o *Obj) Wstat(ctx npo.CtxI, st *np.Stat) error {
	return nil
}
