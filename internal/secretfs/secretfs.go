// Package secretfs serves the workspace's secret files through FUSE so
// airbag sees every read of them. Reading a secret taints the session:
// from then on data may no longer leave the machine. The files are
// read-only inside the sandbox.
//
// Covered: .env and .env.* at any depth (templates excluded), plus the
// usual credential files a repository should not carry but sometimes
// does (private keys, cloud credentials, .npmrc, .pypirc, *.tfvars).
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
	Rel string   // path relative to the workspace, e.g. "apps/web/.env"
	F   *os.File // the real file, opened before the workspace is branched
}

// OnRead is called for every open, with the reader's pid as seen in the
// sandbox's PID namespace, before any byte is served. An error refuses
// the open, so a read whose taint was not recorded never happens.
type OnRead func(name string, pid uint32) error

// IsSecret reports whether a file's base name is one airbag serves as a
// secret. Templates (.env.example, .env.sample, .env.template) hold no
// secrets and are left alone.
func IsSecret(name string) bool {
	switch {
	case strings.HasSuffix(name, ".example"), strings.HasSuffix(name, ".sample"), strings.HasSuffix(name, ".template"):
		return false
	case name == ".env" || strings.HasPrefix(name, ".env."):
		return true
	case name == ".npmrc" || name == ".pypirc" || name == ".netrc":
		return true
	case name == "credentials" || name == "credentials.json": // aws, gcloud
		return true
	case strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") || strings.HasSuffix(name, ".p12") || strings.HasSuffix(name, ".pfx"):
		return true
	case strings.HasPrefix(name, "id_") && !strings.HasSuffix(name, ".pub"): // id_rsa, id_ed25519
		return true
	case strings.HasSuffix(name, ".tfvars") || strings.HasSuffix(name, ".tfvars.json"):
		return true
	default:
		return false
	}
}

// skipDir names directories not worth walking for secrets: they hold no
// source, only dependencies and history.
func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".venv", "venv", "target", "dist", "build", ".cache":
		return true
	}
	return false
}

// Open finds the workspace's secret files, at any depth, and opens them.
func Open(workspace string) []File {
	var out []File
	for _, rel := range Find(workspace) {
		if f, err := os.Open(filepath.Join(workspace, rel)); err == nil {
			out = append(out, File{Rel: rel, F: f})
		}
	}
	return out
}

// Find lists the workspace's secret files, relative to it.
func Find(workspace string) []string {
	var out []string
	_ = filepath.WalkDir(workspace, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // the walk has at least the agent's rights: what it cannot read, the agent cannot either
		}
		if d.IsDir() {
			if p != workspace && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !IsSecret(d.Name()) {
			return nil
		}
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() {
			return nil //nolint:nilerr // a file gone since the walk listed it has nothing to serve
		}
		if rel, err := filepath.Rel(workspace, p); err == nil {
			out = append(out, rel)
		}
		return nil
	})
	return out
}

type root struct {
	fs.Inode
	files  []File
	onRead OnRead
}

func (r *root) OnAdd(ctx context.Context) {
	for _, f := range r.files {
		// Build the directories of f.Rel, then the file leaf, so the
		// served path matches where the file sits in the workspace.
		parent := &r.Inode
		parts := strings.Split(filepath.ToSlash(f.Rel), "/")
		for _, d := range parts[:len(parts)-1] {
			ch := parent.GetChild(d)
			if ch == nil {
				ch = parent.NewPersistentInode(ctx, &fs.Inode{}, fs.StableAttr{Mode: syscall.S_IFDIR})
				parent.AddChild(d, ch, false)
			}
			parent = ch
		}
		leaf := parent.NewPersistentInode(ctx, &secretFile{f: f.F, name: f.Rel, onRead: r.onRead}, fs.StableAttr{Mode: syscall.S_IFREG})
		parent.AddChild(parts[len(parts)-1], leaf, false)
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
		if err := s.onRead(s.name, caller.Pid); err != nil {
			return nil, 0, syscall.EACCES
		}
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
