package authd

import (
	"errors"
	"sync"
	"fmt"
	"github.com/google/uuid"
	sp "sigmaos/sigmap"
)

type authReq struct {
	fid   sp.Tfid
	uname string
	aname string
}

type AuthUser struct {
	uuid   string
	pubkey string

	aws_key    string
	aws_secret string
	aws_region string
}

type AuthMap struct {
	sync.Mutex
	authmap map[string]AuthUser
	uuidmap map[string]string
}

func MkAuthMap() *AuthMap {
	am := &AuthMap{}
	am.authmap = make(map[string]AuthUser)
	am.uuidmap = make(map[string]string)
	return am
}

func (a AuthUser) String() string {
	return fmt.Sprintf("%s:%s:%s:%s:", a.uuid, a.aws_key, a.aws_secret, a.aws_region)
}

func (am *AuthMap) CreateUser(uname string, pubkey string) error {
	am.Lock()
	defer am.Unlock()

	user := AuthUser{}
	user.pubkey = pubkey

	_, ok := am.authmap[uname]
	if ok {
		return errors.New("uname already exists")
	}
	am.authmap[uname] = user

	return nil
}

func (am *AuthMap) UpdateKey(uname string, pubkey string) error {
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

func (am *AuthMap) UpdateAWS(uname string, aws_key string, aws_secret string, aws_region string) error {
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

func (am *AuthMap) UpdateUUID(uname string, uuid string) (string, error) {
	am.Lock()
	defer am.Unlock()

	found, ok := am.authmap[uname]
	if ok {
		found.uuid = uuid
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
func (am *AuthMap) CreateUUID(uname string) (string, error) {
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
func (am *AuthMap) LookupUname(uname string) (AuthUser, error) {
	am.Lock()
	defer am.Unlock()

	found, ok := am.authmap[uname]
	if ok {
		return found, nil
	}

	return AuthUser{}, errors.New("Can't find uname")

}
func (am *AuthMap) LookupUuid(uuid string) (AuthUser, error) {
	am.Lock()
	defer am.Unlock()

	found, ok := am.uuidmap[uuid]
	if ok {
		found1, ok := am.authmap[found]
		if ok {
			return found1, nil
		}
	}

	return AuthUser{}, errors.New("Can't find uuid")
}

