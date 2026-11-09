//go:build !plan9
// +build !plan9

package sftp

import (
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const outbound = "../outbound"

func getChrootTuple(t *testing.T) (string, ClientWrapper) {
	return getChrootTupleWith(t, nil, nil)
}

// getChrootTupleWith starts a chroot request server on <tmp>/sftp.
// rootArg, if set, turns that path into the string passed to ChrootHandler,
// and setup, if set, adjusts the handler before the server starts.
func getChrootTupleWith(t *testing.T, rootArg func(sftpRoot string) string, setup func(*chroot)) (string, ClientWrapper) {
	testRoot, err := ioutil.TempDir(os.TempDir(), "sftp")
	require.NoError(t, err)
	sftpRoot := filepath.Join(testRoot, "sftp")
	require.NoError(t, os.MkdirAll(sftpRoot, 0755))
	require.NoError(t, ioutil.WriteFile(filepath.Join(sftpRoot, outbound), []byte("outbound"), 0644))

	cr, sw := io.Pipe()
	sr, cw := io.Pipe()

	arg := sftpRoot
	if rootArg != nil {
		arg = rootArg(sftpRoot)
	}
	chroot, handlers := ChrootHandler(arg)
	if setup != nil {
		setup(chroot)
	}
	server := NewRequestServer(struct {
		io.Reader
		io.WriteCloser
	}{sr, sw}, handlers)
	served := make(chan error, 1)
	go func() {
		served <- server.Serve()
	}()
	// NewClientPipe() will hung up until server.Serve(),
	// make sure start server first
	client, err := NewClientPipe(cr, cw)
	require.NoError(t, err)
	return sftpRoot, ClientWrapper{
		Client:   client,
		server:   server,
		chroot:   chroot,
		served:   served,
		testRoot: testRoot,
	}
}

func AssertDirExist(t *testing.T, absPath string) bool {
	f, err := os.Lstat(absPath)
	return assert.NoError(t, err) && assert.True(t, f.IsDir())
}

func AssertNoDirExist(t *testing.T, absPath string) bool {
	_, err := os.Lstat(absPath)
	return assert.True(t, os.IsNotExist(err))
}

type ClientWrapper struct {
	*Client
	server   *RequestServer
	chroot   *chroot
	served   chan error
	testRoot string
}

// Close shuts the session down and checks that it ended cleanly, with no transfer error.
func (w ClientWrapper) Close(t *testing.T) {
	assert.NoError(t, w.server.Close())
	assert.NoError(t, w.Client.Close())
	// Err may only be read after Serve() has returned.
	assert.ErrorIs(t, <-w.served, io.EOF)
	assert.NoError(t, w.chroot.Err)
	assert.NoError(t, os.RemoveAll(w.testRoot))
}

func TestChrootStat(t *testing.T) {
	rootPath, client := getChrootTuple(t)
	defer client.Close(t)
	const (
		regular = "regular"
		symlink = "symlink"
		outlink = "outlink"
	)
	// prepare, create file and symlink for stat
	content := []byte(strings.Repeat("hello sftp", 1024))
	require.NoError(t, ioutil.WriteFile(filepath.Join(rootPath, regular), content, 0644))
	require.NoError(t, os.Symlink(filepath.Join(rootPath, regular), filepath.Join(rootPath, symlink)))
	require.NoError(t, os.Symlink(filepath.Join(rootPath, outbound), filepath.Join(rootPath, outlink)))

	// stat a regular file
	f, err := client.Stat(regular)
	if assert.NoError(t, err) {
		assert.EqualValues(t, regular, f.Name())
		assert.EqualValues(t, len(content), f.Size())
		assert.True(t, f.Mode().IsRegular())
	}

	// stat a symlinked file
	f, err = client.Stat(symlink)
	if assert.NoError(t, err) {
		assert.EqualValues(t, symlink, f.Name())
		// Stat() should retrieve file info which symlink point to
		assert.EqualValues(t, len(content), f.Size())
		assert.True(t, f.Mode().IsRegular())
	}

	// outer path will be converted relative to root, and /{root}/outbound does not exist
	_, err = client.Lstat(outbound)
	assert.ErrorIs(t, err, os.ErrNotExist)

	// also, make sure the Stat on the link (which tries to resolve and stat the target) does not work
	_, err = client.Stat(outlink)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestChrootLstat(t *testing.T) {
	rootPath, client := getChrootTuple(t)
	defer client.Close(t)
	const (
		regular = "regular"
		symlink = "symlink"
	)
	// prepare, create file and symlink for stat
	content := []byte(strings.Repeat("hello sftp", 1024))
	require.NoError(t, ioutil.WriteFile(filepath.Join(rootPath, regular), content, 0644))
	require.NoError(t, os.Symlink(filepath.Join(rootPath, regular), filepath.Join(rootPath, symlink)))

	// lstat a regular file
	f, err := client.Lstat(regular)
	if assert.NoError(t, err) {
		// same as Stat()
		assert.EqualValues(t, regular, f.Name())
		assert.EqualValues(t, len(content), f.Size())
		assert.True(t, f.Mode().IsRegular())
	}

	// lstat a symlink file
	f, err = client.Lstat(symlink)
	if assert.NoError(t, err) {
		assert.EqualValues(t, symlink, f.Name())
		// we don't care symlink's size
		// different to Stat(), Lstat() read symlink itself
		assert.Equal(t, os.ModeSymlink, f.Mode().Type())
	}

	// outer path will be converted relate to root, and /{root}/outbound is not exist
	_, err = client.Lstat(outbound)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestChrootReadLink(t *testing.T) {
	rootPath, client := getChrootTuple(t)
	defer client.Close(t)
	const (
		regular = "/path/regular"
		symlink = "symlink"
		outlink = "outlink"
	)
	// prepare, create file and symlink for stat
	content := []byte(strings.Repeat("hello sftp", 1024))
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(rootPath, regular)), 0755))
	require.NoError(t, ioutil.WriteFile(filepath.Join(rootPath, regular), content, 0644))
	require.NoError(t, os.Symlink(filepath.Join(rootPath, regular), filepath.Join(rootPath, symlink)))
	require.NoError(t, os.Symlink(filepath.Join(rootPath, outbound), filepath.Join(rootPath, outlink)))

	// ReadLink should return symlink's target path
	f, err := client.ReadLink(symlink)
	if assert.NoError(t, err) {
		assert.Equal(t, regular, f)
	}

	// we don't want client user to be able to escape the root
	_, err = client.ReadLink(outbound)
	assert.Error(t, err)

	// cannot ReadLink a symlink point to outer file
	_, err = client.ReadLink(outlink)
	assert.Error(t, err)
}

func TestChrootRealPath(t *testing.T) {
	_, client := getChrootTuple(t)
	defer client.Close(t)

	p, err := client.RealPath(".")
	if assert.NoError(t, err) {
		assert.Equal(t, "/", p)
	}
	// outer path will be converted relate to root, so "/../" equals "/"
	p, err = client.RealPath("..")
	if assert.NoError(t, err) {
		assert.Equal(t, "/", p)
	}
	p, err = client.RealPath("./some/path/../to/../here")
	if assert.NoError(t, err) {
		assert.Equal(t, "/some/here", p)
	}
}

func TestChrootMkdir(t *testing.T) {
	rootPath, client := getChrootTuple(t)
	defer client.Close(t)

	const (
		dirPath    = "/mkdir"
		nestedPath = "/nested/should/fail"
	)

	assert.NoError(t, client.Mkdir(dirPath))
	// dir should be created
	AssertDirExist(t, filepath.Join(rootPath, dirPath))
	// cannot create nested dir
	assert.Error(t, client.Mkdir(nestedPath))
	AssertNoDirExist(t, filepath.Join(rootPath, nestedPath))
	// nested dir can create by MkdirAll
	assert.NoError(t, client.MkdirAll(nestedPath))
	AssertDirExist(t, filepath.Join(rootPath, nestedPath))

	// outer path will be converted relate to root
	assert.NoError(t, client.Mkdir("../newdir"))
	AssertDirExist(t, filepath.Join(rootPath, "newdir"))
}

func TestChrootRmdir(t *testing.T) {
	rootPath, client := getChrootTuple(t)
	defer client.Close(t)

	const (
		dirPath    = "/rmdir"
		nestedFile = "/rmdir/nested"
	)
	// prepare
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, dirPath), 0755))
	require.NoError(t, ioutil.WriteFile(filepath.Join(rootPath, nestedFile), []byte("some file"), 0644))
	// cannot remove a file
	assert.Error(t, client.RemoveDirectory(nestedFile))
	// cannot remove a dir not empty
	assert.Error(t, client.RemoveDirectory(dirPath))
	// remove nested file, than remove an empty dir
	require.NoError(t, os.Remove(filepath.Join(rootPath, nestedFile)))
	assert.NoError(t, client.RemoveDirectory(dirPath))
	// dir should be removed
	AssertNoDirExist(t, filepath.Join(rootPath, dirPath))

	// outer path will be converted relate to root, and /{root}/outbound is not exist
	assert.ErrorIs(t, client.RemoveDirectory("../outbound"), os.ErrNotExist)
}

func TestChrootRead(t *testing.T) {
	rootPath, client := getChrootTuple(t)
	defer client.Close(t)

	const (
		fileName = "writefile"
		dirName  = "dir"
	)
	content := []byte(strings.Repeat("hello sftp", 1024))
	require.NoError(t, ioutil.WriteFile(filepath.Join(rootPath, fileName), content, 0644))
	// we can read file from SFTP, and content should be same as local file
	file, err := client.Open(fileName)
	if assert.NoError(t, err) {
		defer file.Close()
		bytes, err := ioutil.ReadAll(file)
		if assert.NoError(t, err) {
			assert.EqualValues(t, content, bytes)
		}
	}
	// cannot open a dir
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, dirName), 0755))
	_, err = client.Open(dirName)
	assert.Error(t, err)

	// outer path will be converted relate to root, and /{root}/outbound is not exist
	_, err = client.Open(outbound)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestChrootWrite(t *testing.T) {
	rootPath, client := getChrootTuple(t)
	defer client.Close(t)

	const (
		fileName = "writefile"
		dirName  = "dir"
	)
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, dirName), 0755))
	writeOverSFTP := func(t *testing.T, file string, content []byte) bool {
		f, err := client.Create(file)
		if assert.NoError(t, err) {
			defer f.Close()
			n, err := f.Write(content)
			return assert.NoError(t, err) &&
				assert.EqualValues(t, len(content), n)
		}
		return false
	}
	checkLocalFile := func(t *testing.T, file string, content []byte) {
		bytes, err := ioutil.ReadFile(filepath.Join(rootPath, file))
		if assert.NoError(t, err) {
			assert.EqualValues(t, content, bytes)
		}
	}
	content := []byte(strings.Repeat("hello sftp", 1024))
	// cannot write dir
	_, err := client.Create(dirName)
	assert.Error(t, err)
	// write a new file and check result
	if writeOverSFTP(t, fileName, content) {
		checkLocalFile(t, fileName, content)
	}
	// truncate and write an exist file
	content = []byte(strings.Repeat("new content", 1024))
	if writeOverSFTP(t, fileName, content) {
		checkLocalFile(t, fileName, content)
	}
	// outer path will be converted relate to root
	f, err := client.Create(outbound)
	f.Close()
	assert.NoError(t, err)
	assert.FileExists(t, filepath.Join(rootPath, filepath.Base(outbound)))
}

func TestChrootRemove(t *testing.T) {
	rootPath, client := getChrootTuple(t)
	defer client.Close(t)

	const (
		dirName  = "dir"
		fileName = "file-to-remove"
	)
	// prepare
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, dirName), 0755))
	require.NoError(t, ioutil.WriteFile(filepath.Join(rootPath, fileName), []byte{}, 0644))
	// file should be removed
	assert.NoError(t, client.Remove(fileName))
	assert.NoFileExists(t, filepath.Join(rootPath, fileName))
	// remove non-exist file should fail
	assert.Error(t, client.Remove(fileName))
	// can remove a folder
	assert.NoError(t, client.Remove(dirName))
	AssertNoDirExist(t, filepath.Join(rootPath, dirName))

	// outer path will be converted relate to root, and /{root}/outbound is not exist
	assert.ErrorIs(t, client.Remove(outbound), os.ErrNotExist)
}

func TestChrootRename(t *testing.T) {
	rootPath, client := getChrootTuple(t)
	defer client.Close(t)

	const (
		oldfile = "oldfile"
		newfile = "newfile"
		extfile = "extfile"
		olddir  = "olddir"
		newdir  = "newdir"
	)
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, olddir), 0755))
	require.NoError(t, ioutil.WriteFile(filepath.Join(rootPath, oldfile), []byte{}, 0644))
	require.NoError(t, ioutil.WriteFile(filepath.Join(rootPath, extfile), []byte{}, 0644))
	// call sftp cmd
	assert.NoError(t, client.Rename(oldfile, newfile))
	// check result, ori file should rename to new
	assert.NoFileExists(t, filepath.Join(rootPath, oldfile))
	assert.FileExists(t, filepath.Join(rootPath, newfile))
	// unlike POSIX, SFTP forbid rename to an exist file
	assert.Error(t, client.Rename(newfile, extfile))
	// can rename a folder
	assert.NoError(t, client.Rename(olddir, newdir))
	AssertDirExist(t, filepath.Join(rootPath, newdir))

	// we don't want client user escape the root
	assert.Error(t, client.Rename(outbound, olddir))
}

func TestChrootSymlink(t *testing.T) {
	rootPath, client := getChrootTuple(t)
	defer client.Close(t)

	const (
		regular = "/path/regular"
		symlink = "symlink"
	)
	// prepare
	content := []byte(strings.Repeat("hello sftp", 1024))
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(rootPath, regular)), 0755))
	require.NoError(t, ioutil.WriteFile(filepath.Join(rootPath, regular), content, 0644))
	// call sftp cmd
	assert.NoError(t, client.Symlink(regular, symlink))
	// symlink should be created
	f, err := os.Lstat(filepath.Join(rootPath, symlink))
	if assert.NoError(t, err) {
		assert.EqualValues(t, filepath.Base(symlink), f.Name())
		assert.Equal(t, fs.ModeSymlink, f.Mode().Type())
	}
	// cannot symlink out of root
	assert.Error(t, client.Symlink(outbound, symlink))
}

func TestChrootReadDir(t *testing.T) {
	rootPath, client := getChrootTuple(t)
	defer client.Close(t)
	const (
		FILE_CNT = 10
		MAX_SIZE = 1024
	)
	rand.Seed(time.Now().UnixNano())
	files := make(map[string]int)
	bytes := make([]byte, MAX_SIZE)
	require.NoError(t, os.MkdirAll(filepath.Join(rootPath, "readdir"), 0755))
	// TODO: generate complicate file tree
	for i := 0; i < FILE_CNT; i++ {
		fileName := fmt.Sprintf("file_%d", i)
		filePath := filepath.Join(rootPath, "readdir", fileName)
		fileSize := rand.Intn(MAX_SIZE)
		require.NoError(t, ioutil.WriteFile(filePath, bytes[:fileSize], 0644))
		files[fileName] = fileSize
	}

	stats, err := client.ReadDir("/readdir")
	require.NoError(t, err)
	res := make(map[string]int)
	for _, stat := range stats {
		res[stat.Name()] = int(stat.Size())
	}
	assert.EqualValues(t, files, res)
}

// closeExpectingTransferError shuts the session down like ClientWrapper.Close,
// but returns the session's transfer error instead of requiring it to be nil.
func closeExpectingTransferError(t *testing.T, w ClientWrapper) error {
	assert.NoError(t, w.server.Close())
	assert.NoError(t, w.Client.Close())
	<-w.served
	assert.NoError(t, os.RemoveAll(w.testRoot))
	return w.chroot.Err
}

func TestChrootSymlinkToParent(t *testing.T) {
	rootPath, client := getChrootTuple(t)
	defer client.Close(t)

	// The request server passes the symlink target through uncleaned,
	// so ".." reaches the handler as the parent of the root.
	// A link to it would expose everything next to the root.
	assert.Error(t, client.Symlink("..", "/up"))
	_, err := os.Lstat(filepath.Join(rootPath, "up"))
	assert.ErrorIs(t, err, os.ErrNotExist)

	// A link to the root's parent placed on disk must not be followed or revealed either.
	require.NoError(t, os.Symlink(filepath.Dir(rootPath), filepath.Join(rootPath, "parentlink")))
	_, err = client.ReadLink("/parentlink")
	assert.Error(t, err)
	_, err = client.Stat("/parentlink")
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestChrootUncleanRootPath(t *testing.T) {
	for name, rootArg := range map[string]func(t *testing.T, root string) string{
		"trailing slash": func(t *testing.T, root string) string { return root + "/" },
		"dot component":  func(t *testing.T, root string) string { return root + "/./" },
		"relative": func(t *testing.T, root string) string {
			t.Chdir(filepath.Dir(root))
			return "./" + filepath.Base(root)
		},
	} {
		t.Run(name, func(t *testing.T) {
			rootPath, client := getChrootTupleWith(t, func(root string) string { return rootArg(t, root) }, nil)
			defer client.Close(t)

			// the root itself must be listable
			_, err := client.ReadDir("/")
			assert.NoError(t, err)

			f, err := client.Create("/file")
			if assert.NoError(t, err) {
				_, err = f.Write([]byte("data"))
				assert.NoError(t, err)
				assert.NoError(t, f.Close())
			}
			assert.FileExists(t, filepath.Join(rootPath, "file"))

			// links the client creates must resolve to files inside the root,
			// which a relative rootPath would break: the target is resolved from the link's directory
			require.NoError(t, client.Symlink("/file", "/link"))
			target, err := os.Readlink(filepath.Join(rootPath, "link"))
			if assert.NoError(t, err) {
				assert.True(t, filepath.IsAbs(target), "link target %q should be absolute", target)
			}
			fi, err := client.Stat("/link")
			if assert.NoError(t, err) {
				assert.EqualValues(t, 4, fi.Size())
			}
			got, err := client.ReadLink("/link")
			if assert.NoError(t, err) {
				assert.Equal(t, "/file", got)
			}
		})
	}
}

func TestChrootToOSFlags(t *testing.T) {
	fs := &chroot{}
	for _, tc := range []struct {
		name  string
		flags uint32
		want  int
	}{
		// a read-only open must not ask for write access,
		// or files the server user can't write become unreadable
		{"read", sshFxfRead, os.O_RDONLY},
		{"write", sshFxfWrite, os.O_WRONLY},
		{"read write", sshFxfRead | sshFxfWrite, os.O_RDWR},
		{"write create trunc", sshFxfWrite | sshFxfCreat | sshFxfTrunc, os.O_WRONLY | os.O_CREATE | os.O_TRUNC},
		{"write create excl", sshFxfWrite | sshFxfCreat | sshFxfExcl, os.O_WRONLY | os.O_CREATE | os.O_EXCL},
	} {
		got, err := fs.toOSFlags(tc.flags)
		if assert.NoError(t, err, tc.name) {
			assert.Equal(t, tc.want, got, tc.name)
		}
	}
	_, err := fs.toOSFlags(sshFxfCreat)
	assert.Error(t, err)
}

func TestChrootTransferErrorOnDisconnect(t *testing.T) {
	_, client := getChrootTuple(t)

	f, err := client.Create("/upload")
	require.NoError(t, err)
	_, err = f.Write([]byte("partial"))
	require.NoError(t, err)

	// drop the connection with the file still open
	err = closeExpectingTransferError(t, client)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestChrootDiskFull(t *testing.T) {
	// The request server sends write-only opens to Filewrite and read-write opens to OpenFile;
	// both must refuse to start an upload on a nearly full disk.
	for name, flags := range map[string]int{
		"at write-only open": os.O_WRONLY | os.O_CREATE | os.O_TRUNC,
		"at read-write open": os.O_RDWR | os.O_CREATE | os.O_TRUNC,
	} {
		t.Run(name, func(t *testing.T) {
			_, client := getChrootTupleWith(t, nil, func(c *chroot) {
				c.freeSpace = func() uint64 { return 0 }
			})
			_, err := client.OpenFile("/upload", flags)
			assert.ErrorContains(t, err, "no space left on device")
			err = closeExpectingTransferError(t, client)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "Out of disk space")
				assert.Contains(t, err.Error(), "/upload")
			}
		})
	}

	t.Run("concurrent writes", func(t *testing.T) {
		var free atomic.Uint64
		free.Store(2 << 30)
		_, client := getChrootTupleWith(t, nil, func(c *chroot) {
			c.freeSpace = free.Load
		})

		const writers = 8
		files := make([]*File, writers)
		for i := range files {
			f, err := client.Create(fmt.Sprintf("/upload%d", i))
			require.NoError(t, err)
			files[i] = f
		}

		// the disk fills up while several uploads are writing at once;
		// the request server runs these writes on parallel workers
		free.Store(0)
		var wg sync.WaitGroup
		for _, f := range files {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := f.Write([]byte("data"))
				assert.ErrorContains(t, err, "no space left on device")
				assert.NoError(t, f.Close())
			}()
		}
		wg.Wait()

		err := closeExpectingTransferError(t, client)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Out of disk space")
		}
	})
}

func TestChrootFailedWriteIsTransferError(t *testing.T) {
	// /dev/full fails every write with ENOSPC
	file, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skip("no /dev/full:", err)
	}
	defer file.Close()

	fs := &chroot{freeSpace: func() uint64 { return 2 << 30 }}
	f := &CheckedFile{file: file, fs: fs}
	_, err = f.WriteAt([]byte("data"), 0)
	require.Error(t, err)
	assert.Equal(t, err, fs.Err)
}
