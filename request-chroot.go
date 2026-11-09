package sftp

import (
	"errors"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// ChrootHandler returns handlers that confine the client to rootPath ("" means "/").
// All access goes through an os.Root, which only follows symlinks that stay inside the root.
// Call Close once Serve has returned to release the root directory.
func ChrootHandler(rootPath string) (*chroot, Handlers) {
	if rootPath == "" {
		rootPath = "/"
	}
	if abs, err := filepath.Abs(rootPath); err == nil {
		rootPath = abs
	} else {
		rootPath = filepath.Clean(rootPath)
	}
	chroot := &chroot{
		rootPath: rootPath,
	}
	chroot.root, chroot.rootErr = os.OpenRoot(rootPath)
	if chroot.rootErr != nil {
		log.Printf("chroot: cannot open root %s: %v", rootPath, chroot.rootErr)
	}
	return chroot, Handlers{chroot, chroot, chroot, chroot}
}

type chroot struct {
	rootPath string
	root     *os.Root
	rootErr  error

	freeSpace func() uint64

	mu sync.Mutex
	// Err holds the first error that broke a transfer in this session:
	// out of disk space, a failed write, or the connection dropping with a file still open.
	// The request server's workers set it concurrently;
	// read it only after Serve() has returned.
	Err error
}

// the real error names the host path, so it only goes to the log
var errRootUnavailable = errors.New("root directory unavailable")

func (fs *chroot) getRoot() (*os.Root, error) {
	if fs.rootErr != nil {
		return nil, errRootUnavailable
	}
	return fs.root, nil
}

// Close releases the root directory.
func (fs *chroot) Close() error {
	if fs.root == nil {
		return nil
	}
	return fs.root.Close()
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
	return fs.diskAvailable()
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

// rel converts a client path ("/a/b") to the root-relative form os.Root takes ("a/b").
func rel(p string) string {
	p = strings.TrimPrefix(cleanPath(p), "/")
	if p == "" {
		return "."
	}
	return filepath.FromSlash(p)
}

// os.Root reports a path that would leave the root with this unexported error
const errPathEscapesText = "path escapes from parent"

// clientErr makes a symlink that leads out of the root look like a missing file.
func clientErr(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) && pe.Err != nil && pe.Err.Error() == errPathEscapesText {
		return os.ErrNotExist
	}
	return err
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

func (fs *chroot) Fileread(r *Request) (io.ReaderAt, error) {
	if r.Flags&sshFxfRead == 0 {
		return nil, os.ErrInvalid
	}
	return fs.OpenFile(r)
}

type CheckedFile struct {
	file *os.File
	fs   *chroot
	name string // as the client sees it
}

// clientErr puts the client's path in errors in place of the host path.
func (f *CheckedFile) clientErr(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return &os.PathError{Op: pe.Op, Path: f.name, Err: pe.Err}
	}
	return err
}

// checkSpace refuses a write of n bytes that would not fit on the disk.
func (f *CheckedFile) checkSpace(n int) error {
	if uint64(n) > f.fs.available() {
		f.fs.diskFull(f.file.Name(), errors.New("Out of disk space, aborting write"))
		return errNoSpace
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
	return n, f.clientErr(err)
}

func (f *CheckedFile) WriteAt(b []byte, off int64) (n int, err error) {
	if err := f.checkSpace(len(b)); err != nil {
		return 0, err
	}
	n, err = f.file.WriteAt(b, off)
	if err != nil {
		f.fs.TransferError(err)
	}
	return n, f.clientErr(err)
}

func (f *CheckedFile) WriterAtReaderAt(b []byte, off int64) (n int, err error) {
	return f.WriteAt(b, off)
}

func (f *CheckedFile) ReadAt(b []byte, off int64) (n int, err error) {
	n, err = f.file.ReadAt(b, off)
	return n, f.clientErr(err)
}

// Close is called by the request server when the handle is closed or the session ends.
func (f *CheckedFile) Close() error {
	err := f.file.Close()
	if err != nil {
		// some filesystems only report a failed write on close
		f.fs.TransferError(err)
	}
	return f.clientErr(err)
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
	// a missing root would otherwise show up as a full disk
	if _, err := fs.getRoot(); err != nil {
		return nil, err
	}
	if r.Flags&sshFxfWrite != 0 && fs.available() < (1024*1024*1024) {
		fs.diskFull(r.Filepath, errors.New("Out of disk space, aborting write of "+r.Filepath))
		return nil, errNoSpace
	}
	return fs.openfile(r.Filepath, r.Flags)
}

func (fs *chroot) openfile(pathname string, flags uint32) (*CheckedFile, error) {
	osFlags, err := fs.toOSFlags(flags)
	if err != nil {
		return nil, err
	}
	root, err := fs.getRoot()
	if err != nil {
		return nil, err
	}
	file, err := root.OpenFile(rel(pathname), osFlags, 0644)
	if err != nil {
		return nil, clientErr(err)
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
	return &CheckedFile{file: file, fs: fs, name: cleanPath(pathname)}, nil
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
	root, err := fs.getRoot()
	if err != nil {
		return err
	}
	// SFTP-v2: "It is an error if there already exists a file with the name specified by newpath."
	// This varies from the POSIX specification, which allows limited replacement of target files.
	if !posix {
		_, err := root.Lstat(rel(newpath))
		if !os.IsNotExist(err) {
			return os.ErrExist
		}
	}
	return clientErr(root.Rename(rel(oldpath), rel(newpath)))
}

func (fs *chroot) PosixRename(r *Request) error {
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	return fs.rename(r.Filepath, r.Target, true)
}

func (fs *chroot) StatVFS(r *Request) (*StatVFS, error) {
	root, err := fs.getRoot()
	if err != nil {
		return nil, err
	}
	// statfs by path would follow symlinks out of the root
	f, err := root.Open(rel(r.Filepath))
	if err != nil {
		return nil, clientErr(err)
	}
	defer f.Close()
	return fstatVFS(f)
}

func (fs *chroot) mkdir(pathname string) error {
	root, err := fs.getRoot()
	if err != nil {
		return err
	}
	return clientErr(root.Mkdir(rel(pathname), 0755))
}

func (fs *chroot) rmdir(pathname string) error {
	root, err := fs.getRoot()
	if err != nil {
		return err
	}
	stat, err := root.Lstat(rel(pathname))
	if err != nil {
		return clientErr(err)
	}
	// IEEE 1003.1: If pathname is a symlink, then rmdir should fail with ENOTDIR.
	if stat.Mode()&os.ModeSymlink != 0 || !stat.IsDir() {
		return syscall.ENOTDIR
	}
	return clientErr(root.Remove(rel(pathname)))
}

func (fs *chroot) link(oldpath, newpath string) error {
	root, err := fs.getRoot()
	if err != nil {
		return err
	}
	return clientErr(root.Link(rel(oldpath), rel(newpath)))
}

// symlink() creates a symbolic link named `linkpath` which contains the string `target`.
// NOTE! This would be called with `symlink(req.Filepath, req.Target)` due to different semantics.
func (fs *chroot) symlink(target, linkpath string) error {
	root, err := fs.getRoot()
	if err != nil {
		return err
	}
	stored, err := storedLinkTarget(target, linkpath)
	if err != nil {
		return err
	}
	return clientErr(root.Symlink(stored, rel(linkpath)))
}

// storedLinkTarget converts the target of a client's symlink request to the target written to disk.
// os.Root never follows absolute links, so it is stored relative to the link's directory.
// The request server does not clean the target, and os.Root.Symlink does not check it,
// so a relative target that climbs out of the root ("..") is refused here.
func storedLinkTarget(target, linkpath string) (string, error) {
	if target == "" {
		return "", os.ErrInvalid
	}
	linkDir := filepath.Dir(rel(linkpath))
	var dest string // root-relative
	if path.IsAbs(target) {
		dest = rel(target)
	} else {
		dest = filepath.Join(linkDir, filepath.FromSlash(target))
		if !filepath.IsLocal(dest) {
			return "", os.ErrInvalid
		}
	}
	return filepath.Rel(linkDir, dest)
}

// clientLinkTarget converts a link target read from disk to the absolute path the client sees.
func (fs *chroot) clientLinkTarget(linkpath, target string) (string, error) {
	var dest string // root-relative
	if filepath.IsAbs(target) {
		// Earlier versions of this handler stored host paths under rootPath.
		// os.Root does not follow them, but they can still be shown.
		r, err := filepath.Rel(fs.rootPath, target)
		if err != nil {
			return "", os.ErrNotExist
		}
		dest = r
	} else {
		dest = filepath.Join(filepath.Dir(rel(linkpath)), target)
	}
	if !filepath.IsLocal(dest) {
		return "", os.ErrNotExist
	}
	return cleanPath(filepath.ToSlash(dest)), nil
}

func (fs *chroot) unlink(pathname string) error {
	root, err := fs.getRoot()
	if err != nil {
		return err
	}
	stat, err := root.Lstat(rel(pathname))
	if err != nil {
		return clientErr(err)
	}
	if stat.IsDir() {
		// IEEE 1003.1: implementations may opt out of allowing the unlinking of directories.
		// SFTP-v2: SSH_FXP_REMOVE may not remove directories.
		return os.ErrInvalid
	}
	return clientErr(root.Remove(rel(pathname)))
}

func (fs *chroot) Filelist(r *Request) (ListerAt, error) {
	_ = r.WithContext(r.Context()) // initialize context for deadlock testing
	root, err := fs.getRoot()
	if err != nil {
		return nil, err
	}
	name := rel(r.Filepath)
	switch r.Method {
	case "List":
		dir, err := root.Open(name)
		if err != nil {
			return nil, clientErr(err)
		}
		defer dir.Close()
		files, err := dir.ReadDir(-1)
		if err != nil {
			return nil, clientErr(err)
		}
		var res listerat = make(listerat, 0, len(files))
		for _, file := range files {
			// an lstat relative to the directory, since it was opened through os.Root
			stat, err := file.Info()
			if os.IsNotExist(err) {
				continue // removed since the directory was read
			}
			if err != nil {
				return nil, clientErr(err)
			}
			res = append(res, stat)
		}
		return res, nil

	case "Stat":
		file, err := root.Stat(name)
		if err != nil {
			return nil, clientErr(err)
		}
		return listerat{file}, nil

	case "Readlink":
		target, err := root.Readlink(name)
		if err != nil {
			return nil, clientErr(err)
		}
		res, err := fs.clientLinkTarget(r.Filepath, target)
		if err != nil {
			return nil, err
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
	root, err := fs.getRoot()
	if err != nil {
		return nil, err
	}
	fi, err := root.Lstat(rel(r.Filepath))
	if err != nil {
		return nil, clientErr(err)
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
