package authsrv_test

import (
	"github.com/stretchr/testify/assert"
	"sigmaos/test"
	"testing"

)

func TestAuthSrvRun(t *testing.T) {
	// start server
	ts := test.MakeTstateAll(t)
    
	// Stop server
	assert.Nil(t, ts.Shutdown())
}


