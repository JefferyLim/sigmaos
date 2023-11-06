package authsrv

import (
    "sync"
    "errors"

    sp "sigmaos/sigmap"
    "github.com/google/uuid"

)

type authReq struct {
    fid sp.Tfid
    uname string
    aname string
}

type authUser struct {
    uuid string
    pubkey string
}

type authMap struct {
    sync.Mutex
    authmap map[string]authUser
}

func mkAuthMap() * authMap {
    am := &authMap{}
    am.authmap = make(map[string]authUser)
    return am
}

func (am * authMap) createUser(uname string, pubkey string) {
    am.Lock()
    defer am.Unlock()

    user := authUser{}
    user.pubkey = pubkey

    am.authmap[uname] = user
}

func (am * authMap) updateKey(uname string, pubkey string) error {
    am.Lock()
    defer am.Unlock()

    found, ok := am.authmap[uname]
    if(ok) {
        found.pubkey = pubkey
        am.authmap[uname] = found
        
        return nil
    }
    return errors.New("Can't find uname")

}

func (am * authMap) createUUID(uname string) (string, error) {
    am.Lock()
    defer am.Unlock()

    found, ok := am.authmap[uname]
    if(ok) {
        found.uuid = uuid.New().String()
        am.authmap[uname] = found
        return found.uuid, nil
    }

    return "", errors.New("Can't find uname")

}
/*
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
*/
