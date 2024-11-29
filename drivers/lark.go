//go:build (linux || darwin || windows) && (amd64 || arm64)
// +build linux darwin windows
// +build amd64 arm64

package drivers

import (
	_ "github.com/coordinate/alist/drivers/lark"
)
