//go:build !darwin && !linux
// +build !darwin,!linux

package sftp

import (
	"errors"
	"math"
	"os"
)

var errNoSpace = errors.New("no space left on device")

// diskAvailable has no portable implementation here, so the free space checks never trigger.
func (fs *chroot) diskAvailable() uint64 {
	return math.MaxUint64
}

func fstatVFS(f *os.File) (*StatVFS, error) {
	return nil, ErrSSHFxOpUnsupported
}
