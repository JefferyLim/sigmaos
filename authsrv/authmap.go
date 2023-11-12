package authsrv

import (
	"errors"
	"sync"

	"github.com/google/uuid"
	sp "sigmaos/sigmap"
)

type authReq struct {
	fid   sp.Tfid
	uname string
	aname string
}

type authUser struct {
	uuid   string
	pubkey string

	aws_key    string
	aws_secret string
	aws_region string
}

type authMap struct {
	sync.Mutex
	authmap map[string]authUser
	uuidmap map[string]string
}

func mkAuthMap() *authMap {
	am := &authMap{}
	am.authmap = make(map[string]authUser)
	am.uuidmap = make(map[string]string)
	return am
}

func (am *authMap) createUser(uname string, pubkey string) error {
	am.Lock()
	defer am.Unlock()

	user := authUser{}
	user.pubkey = pubkey

	_, ok := am.authmap[uname]
	if ok {
		return errors.New("uname already exists")
	}
	am.authmap[uname] = user

	return nil
}

func (am *authMap) updateKey(uname string, pubkey string) error {
	am.Lock()
	defer am.Unlock()

	found, ok := am.authmap[uname]
	if ok {
		found.pubkey = pubkey
		am.authmap[uname] = found

		return nil
	}
	return errors.New("Can't find uname")

}

func (am *authMap) updateAWS(uname string, aws_key string, aws_secret string, aws_region string) error {
	am.Lock()
	defer am.Unlock()

	found, ok := am.authmap[uname]
	if ok {
		found.aws_key = aws_key
		found.aws_secret = aws_secret
		found.aws_region = aws_region

		am.authmap[uname] = found
		return nil
	}

	return errors.New("Can't find uname")

}

func (am *authMap) createUUID(uname string) (string, error) {
	am.Lock()
	defer am.Unlock()

	found, ok := am.authmap[uname]
	if ok {
		found.uuid = uuid.New().String()
		am.authmap[uname] = found

		_, ok := am.uuidmap[found.uuid]
		if ok {
			return "", errors.New("UUID already exists in table")
		} else {
			am.uuidmap[found.uuid] = uname
		}
		return found.uuid, nil
	}

	return "", errors.New("Can't find uname")

}
func (am *authMap) lookupUname(uname string) (authUser, error) {
	am.Lock()
	defer am.Unlock()

	found, ok := am.authmap[uname]
	if ok {
		return found, nil
	}

	return authUser{}, errors.New("Can't find uname")

}
func (am *authMap) lookupUuid(uuid string) (authUser, error) {
	am.Lock()
	defer am.Unlock()

	found, ok := am.uuidmap[uuid]
	if ok {
		found1, ok := am.authmap[found]
		if ok {
			return found1, nil
		}
	}

	return authUser{}, errors.New("Can't find uuid")
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
