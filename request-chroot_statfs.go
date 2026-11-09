//go:build darwin || linux
// +build darwin linux

package sftp

import (
	"os"
	"syscall"
)

// statusFromError sends the error text, so the client sees "no space left on device"
var errNoSpace error = syscall.ENOSPC

func (fs *chroot) diskAvailable() uint64 {
	return NewDiskUsage(fs.rootPath).Available()
}

func fstatVFS(f *os.File) (*StatVFS, error) {
	var stat syscall.Statfs_t
	if err := syscall.Fstatfs(int(f.Fd()), &stat); err != nil {
		return nil, err
	}
	return statvfsFromStatfst(&stat)
}

// DiskUsage contains usage data and provides user-friendly access methods
type DiskUsage struct {
	stat *syscall.Statfs_t
}

// NewDiskUsages returns an object holding the disk usage of volumePath
// or nil in case of error (invalid path, etc)
func NewDiskUsage(volumePath string) *DiskUsage {

	var stat syscall.Statfs_t
	syscall.Statfs(volumePath, &stat)
	return &DiskUsage{&stat}
}

// Available return total available bytes on file system to an unprivileged user
func (du *DiskUsage) Available() uint64 {
	return du.stat.Bavail * uint64(du.stat.Bsize)
}
