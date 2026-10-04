// Package secretfs serves the workspace's .env files through FUSE so
// airbag sees every read of them. Reading a secret taints the session:
// from then on data may no longer leave the machine. The files are
// read-only inside the sandbox.
package secretfs

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type File struct {
	Name string   // base name, e.g. ".env.local"
	F    *os.File // the real file, opened before the workspace is branched
}

// OnRead is called for every open, with the reader's pid as seen in the
// sandbox's PID namespace.
type OnRead func(name string, pid uint32)

// Open finds the workspace's .env files. Templates (.env.example,
// .env.sample, .env.template) hold no secrets and are left alone.
func Open(workspace string) []File {
	paths, _ := filepath.Glob(filepath.Join(workspace, ".env*"))
	var out []File
	for _, p := range paths {
		name := filepath.Base(p)
		if strings.HasSuffix(name, ".example") || strings.HasSuffix(name, ".sample") || strings.HasSuffix(name, ".template") {
			continue
		}
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if f, err := os.Open(p); err == nil {
			out = append(out, File{Name: name, F: f})
		}
	}
	return out
}

type root struct {
	fs.Inode
	files  []File
	onRead OnRead
}

func (r *root) OnAdd(ctx context.Context) {
	for _, f := range r.files {
		ch := r.NewPersistentInode(ctx, &secretFile{f: f.F, name: f.Name, onRead: r.onRead}, fs.StableAttr{Mode: syscall.S_IFREG})
		r.AddChild(f.Name, ch, false)
	}
}

type secretFile struct {
	fs.Inode
	f      *os.File
	name   string
	onRead OnRead
}

var (
	_ fs.NodeOpener    = (*secretFile)(nil)
	_ fs.NodeReader    = (*secretFile)(nil)
	_ fs.NodeGetattrer = (*secretFile)(nil)
	_ fs.NodeSetattrer = (*secretFile)(nil)
)

func (s *secretFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if flags&(syscall.O_WRONLY|syscall.O_RDWR|syscall.O_TRUNC) != 0 {
		return nil, 0, syscall.EROFS
	}
	if caller, ok := fuse.FromContext(ctx); ok && s.onRead != nil {
		s.onRead(s.name, caller.Pid)
	}
	return nil, fuse.FOPEN_DIRECT_IO, 0
}

func (s *secretFile) Read(_ context.Context, _ fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	n, err := s.f.ReadAt(dest, off)
	if err != nil && err != io.EOF {
		return nil, fs.ToErrno(err)
	}
	return fuse.ReadResultData(dest[:n]), 0
}

func (s *secretFile) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	st, err := s.f.Stat()
	if err != nil {
		return fs.ToErrno(err)
	}
	out.Mode = syscall.S_IFREG | uint32(st.Mode().Perm())&^0o222
	out.Size = uint64(st.Size())
	t := st.ModTime()
	out.SetTimes(&t, &t, &t)
	return 0
}

func (s *secretFile) Setattr(context.Context, fs.FileHandle, *fuse.SetAttrIn, *fuse.AttrOut) syscall.Errno {
	return syscall.EROFS
}

// Mount serves the files in dir. It mounts directly (the caller is root
// of its user namespace), without fusermount.
func Mount(dir string, files []File, onRead OnRead) (*fuse.Server, error) {
	zero := time.Duration(0) // no caching: every open reaches us
	opts := &fs.Options{
		MountOptions: fuse.MountOptions{DirectMount: true, DirectMountStrict: true, FsName: "airbag-secrets", Name: "airbag"},
		AttrTimeout:  &zero,
		EntryTimeout: &zero,
	}
	return fs.Mount(dir, &root{files: files, onRead: onRead}, opts)
}
