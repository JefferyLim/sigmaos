package authsrv

import (
    "sync"
    "errors"

    sp "sigmaos/sigmap"

)


type authInfo struct {
    afid sp.Tfid
    authenticated bool
}

type authReq struct {
    fid sp.Tfid
    uname string
    aname string
}

type authMap struct {
    sync.Mutex
    next sp.Tfid
    authmap map[authReq]authInfo
}

func mkAuthMap() * authMap {
    am := &authMap{}
    am.authmap = make(map[authReq]authInfo)
    am.next = 2
    return am
}

func (am * authMap) allocAuth(req authReq) sp.Tfid {
    am.Lock()
    defer am.Unlock()
    
    afid := am.next
    am.next += 1
    
    info := authInfo{}
    info.afid = afid
    info.authenticated = false

    am.authmap[req] = info

    return afid
}

func (am * authMap) authenticate(req authReq) {
    am.Lock()
    defer am.Unlock()

    if ai, ok := am.authmap[req]; ok {
        ai.authenticated = true
        am.authmap[req] = ai    
    }
}

func (am * authMap) lookup(req authReq) (authInfo, error) {
    am.Lock()
    defer am.Unlock()

    // Search for info
    found, ok := am.authmap[req]

    if(ok) {
        return found, nil
    }

    return  found, errors.New("authMap lookup failed")
}
