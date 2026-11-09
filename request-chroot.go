package sftp

import (
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

func ChrootHandler(rootPath string) (*chroot, Handlers) {
	if rootPath != "" {
		if abs, err := filepath.Abs(rootPath); err == nil {
			rootPath = abs
		} else {
			rootPath = filepath.Clean(rootPath)
		}
	}
	chroot := &chroot{
		rootPath: rootPath,
	}
	return chroot, Handlers{chroot, chroot, chroot, chroot}
}

type chroot struct {
	rootPath string

	freeSpace func() uint64

	mu sync.Mutex
	// Err holds the first error that broke a transfer in this session:
	// out of disk space, a failed write, or the connection dropping with a file still open.
	// The request server's workers set it concurrently;
	// read it only after Serve() has returned.
	Err error
}

// TransferError records err as the session's transfer error unless one is already recorded.
// The request server calls it through CheckedFile when the connection drops with a file open.
func (fs *chroot) TransferError(err error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.Err == nil {
		fs.Err = err
	}
}

func (fs *chroot) available() uint64 {
	if fs.freeSpace != nil {
		return fs.freeSpace()
	}
	return NewDiskUsage(fs.rootPath).Available()
}

// diskFull logs and records an aborted write, once per session.
func (fs *chroot) diskFull(name string, err error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.Err == nil {
		log.Printf("aborting write of %v, disk almost full", name)
		fs.Err = err
	}
}

func (fs *chroot) toOSFlags(flags uint32) (int, error) {
	var osFlags int
	if flags&sshFxfRead != 0 && flags&sshFxfWrite != 0 {
		osFlags |= os.O_RDWR
	} else if flags&sshFxfWrite != 0 {
		osFlags |= os.O_WRONLY
	} else if flags&sshFxfRead != 0 {
		osFlags |= os.O_RDONLY
	} else {
		// how are they opening?
		return 0, syscall.EINVAL
	}
	if flags&sshFxfCreat != 0 {
		osFlags |= os.O_CREATE
	}
	if flags&sshFxfTrunc != 0 {
		osFlags |= os.O_TRUNC
	}
	if flags&sshFxfExcl != 0 {
		osFlags |= os.O_EXCL
	}
	return osFlags, nil
}

func (fs *chroot) getRealPath(p string) (string, error) {
	p = filepath.Join(fs.rootPath, p)
	if fs.rootPath == "" || fs.rootPath == "/" {
		return p, nil
	}
	rel, err := filepath.Rel(fs.rootPath, p)
	if err != nil || !filepath.IsLocal(rel) {
		log.Printf("getRealPath for file %s outside of chroot %s", p, fs.rootPath)
		return "", os.ErrInvalid
	}
	return p, nil
}

func (fs *chroot) getRelativePath(p string) (string, error) {
	if fs.rootPath == "" || fs.rootPath == "/" {
		return cleanPath(p), nil
	}
	rel, err := filepath.Rel(fs.rootPath, p)
	if err != nil || !filepath.IsLocal(rel) {
		return "", os.ErrInvalid
	}
	return cleanPath(rel), nil
}

func (fs *chroot) Fileread(r *Request) (io.ReaderAt, error) {
	if r.Flags&sshFxfRead == 0 {
		return nil, os.ErrInvalid
	}
	return fs.OpenFile(r)
}

type CheckedFile struct {
	file *os.File
	fs   *chroot
}

// checkSpace refuses a write of n bytes that would not fit on the disk.
func (f *CheckedFile) checkSpace(n int) error {
	if uint64(n) > f.fs.available() {
		f.fs.diskFull(f.file.Name(), errors.New("Out of disk space, aborting write"))
		return syscall.ENOSPC
	}
	return nil
}

// TransferError lets the request server report transfers that broke off,
// such as the connection dropping while the file is open.
// CheckedFile is what the server holds, so it never calls chroot.TransferError directly.
func (f *CheckedFile) TransferError(err error) {
	f.fs.TransferError(err)
}

func (f *CheckedFile) Write(b []byte) (n int, err error) {
	if err := f.checkSpace(len(b)); err != nil {
		return 0, err
	}
	n, err = f.file.Write(b)
	if err != nil {
		f.fs.TransferError(err)
	}
	return n, err
}

func (f *CheckedFile) WriteAt(b []byte, off int64) (n int, err error) {
	if err := f.checkSpace(len(b)); err != nil {
		return 0, err
	}
	n, err = f.file.WriteAt(b, off)
	if err != nil {
		f.fs.TransferError(err)
	}
	return n, err
}

func (f *CheckedFile) WriterAtReaderAt(b []byte, off int64) (n int, err error) {
	return f.WriteAt(b, off)
}

func (f *CheckedFile) ReadAt(b []byte, off int64) (n int, err error) {
	return f.file.ReadAt(b, off)
}

func (fs *chroot) Filewrite(r *Request) (io.WriterAt, error) {
	if r.Flags&sshFxfWrite == 0 {
		return nil, os.ErrInvalid
	}
	return fs.OpenFile(r)
}

// OpenFile serves read-write opens directly; the request server sends only write-only opens through Filewrite.
func (fs *chroot) OpenFile(r *Request) (WriterAtReaderAt, error) {
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	if r.Flags&sshFxfWrite != 0 && fs.available() < (1024*1024*1024) {
		fs.diskFull(r.Filepath, errors.New("Out of disk space, aborting write of "+r.Filepath))
		return nil, syscall.ENOSPC
	}
	return fs.openfile(r.Filepath, r.Flags)
}

func (fs *chroot) openfile(pathname string, flags uint32) (*CheckedFile, error) {
	osFlags, err := fs.toOSFlags(flags)
	if err != nil {
		return nil, err
	}
	realPath, err := fs.getRealPath(pathname)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(realPath, osFlags, 0644)
	if err != nil {
		file.Close()
		return nil, err
	}
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if stat.IsDir() {
		file.Close()
		return nil, os.ErrInvalid
	}
	return &CheckedFile{file, fs}, nil
}

func (fs *chroot) Filecmd(r *Request) error {
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	switch r.Method {
	case "Setstat":
		// we just ignore this
		return nil

	case "Rename":
		return fs.rename(r.Filepath, r.Target, false)

	case "Rmdir":
		return fs.rmdir(r.Filepath)

	case "Remove":
		// IEEE 1003.1 remove explicitly can unlink files and remove empty directories.
		// We use instead here the semantics of unlink, which is allowed to be restricted against directories.
		return fs.unlink(r.Filepath)

	case "Mkdir":
		return fs.mkdir(r.Filepath)

	case "Link":
		return fs.link(r.Filepath, r.Target)

	case "Symlink":
		// NOTE: r.Filepath is the target, and r.Target is the linkpath.
		return fs.symlink(r.Filepath, r.Target)
	}

	return errors.New("unsupported")
}

func (fs *chroot) rename(oldpath, newpath string, posix bool) error {
	oldpath, err := fs.getRealPath(oldpath)
	if err != nil {
		return err
	}
	newpath, err = fs.getRealPath(newpath)
	if err != nil {
		return err
	}
	// SFTP-v2: "It is an error if there already exists a file with the name specified by newpath."
	// This varies from the POSIX specification, which allows limited replacement of target files.
	if !posix {
		_, err := os.Lstat(newpath)
		if !os.IsNotExist(err) {
			return os.ErrExist
		}
	}
	return os.Rename(oldpath, newpath)
}

func (fs *chroot) PosixRename(r *Request) error {
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	return fs.rename(r.Filepath, r.Target, true)
}

func (fs *chroot) StatVFS(r *Request) (*StatVFS, error) {
	filepath, err := fs.getRealPath(r.Filepath)
	if err != nil {
		return nil, err
	}
	return getStatVFSForPath(filepath)
}

func (fs *chroot) mkdir(pathname string) error {
	pathname, err := fs.getRealPath(pathname)
	if err != nil {
		return err
	}
	return os.Mkdir(pathname, 0755)
}

func (fs *chroot) rmdir(pathname string) error {
	pathname, err := fs.getRealPath(pathname)
	if err != nil {
		return err
	}
	stat, err := os.Lstat(pathname)
	if err != nil {
		return err
	}
	// IEEE 1003.1: If pathname is a symlink, then rmdir should fail with ENOTDIR.
	if stat.Mode()&os.ModeSymlink != 0 || !stat.IsDir() {
		return syscall.ENOTDIR
	}
	return os.Remove(pathname)
}

func (fs *chroot) link(oldpath, newpath string) error {
	// make sure user cannot escape root path
	oldpath, err := fs.getRealPath(oldpath)
	if err != nil {
		return err
	}
	newpath, err = fs.getRealPath(newpath)
	if err != nil {
		return err
	}
	return os.Link(oldpath, newpath)
}

// symlink() creates a symbolic link named `linkpath` which contains the string `target`.
// NOTE! This would be called with `symlink(req.Filepath, req.Target)` due to different semantics.
func (fs *chroot) symlink(target, linkpath string) error {
	// make sure user cannot escape root path
	target, err := fs.getRealPath(target)
	if err != nil {
		return err
	}
	linkpath, err = fs.getRealPath(linkpath)
	if err != nil {
		return err
	}
	return os.Symlink(target, linkpath)
}

func (fs *chroot) unlink(pathname string) error {
	pathname, err := fs.getRealPath(pathname)
	if err != nil {
		return err
	}
	stat, err := os.Lstat(pathname)
	if err != nil {
		return err
	}
	if stat.IsDir() {
		// IEEE 1003.1: implementations may opt out of allowing the unlinking of directories.
		// SFTP-v2: SSH_FXP_REMOVE may not remove directories.
		return os.ErrInvalid
	}
	return os.Remove(pathname)
}

func (fs *chroot) Filelist(r *Request) (ListerAt, error) {
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	realPath, err := fs.getRealPath(r.Filepath)
	if err != nil {
		return nil, err
	}
	switch r.Method {
	case "List":
		files, err := os.ReadDir(realPath)
		if err != nil {
			return nil, err
		}
		var res listerat = make(listerat, 0, len(files))
		for _, file := range files {
			stat, err := file.Info()
			if err != nil {
				return nil, err
			}
			res = append(res, stat)
		}
		return res, nil

	case "Stat":
		f, err := os.Lstat(realPath)
		if err != nil {
			return nil, err
		}
		if f.Mode()&os.ModeSymlink == os.ModeSymlink {
			target, err := os.Readlink(realPath)
			if err != nil {
				return nil, os.ErrNotExist
			}
			_, err = fs.getRelativePath(target)
			if err != nil {
				return nil, os.ErrNotExist
			}
			realPath = target
		}

		file, err := os.Stat(realPath)
		if err != nil {
			return nil, err
		}
		return listerat{file}, nil

	case "Readlink":
		target, err := os.Readlink(realPath)
		if err != nil {
			return nil, err
		}
		res, err := fs.getRelativePath(target)
		if err != nil {
			return nil, os.ErrNotExist
		}
		// SFTP-v2: The server will respond with a SSH_FXP_NAME packet containing only
		// one name and a dummy attributes value.
		return listerat{
			&chrootFile{
				memFile{
					name: res,
					err:  os.ErrNotExist, // prevent accidental use as a reader/writer.
				},
			},
		}, nil
	}

	return nil, errors.New("unsupported")
}

// implements LstatFileLister interface
func (fs *chroot) Lstat(r *Request) (ListerAt, error) {
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	realPath, err := fs.getRealPath(r.Filepath)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(realPath)
	if err != nil {
		return nil, err
	}
	return listerat{fi}, nil
}

// implements RealpathFileLister interface
func (fs *chroot) Realpath(p string) string {
	return cleanPath(p)
}

type chrootFile struct {
	memFile
}

func (f *chrootFile) Name() string {
	// memFile.Name() only return file base name, not fit for ReadLink
	return f.name
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
