package aliyundrive

import (
	"crypto/ecdsa"

	"github.com/coordinate/alist/pkg/generic_sync"
)

type State struct {
	deviceID   string
	signature  string
	retry      int
	privateKey *ecdsa.PrivateKey
}

var global = generic_sync.MapOf[string, *State]{}
