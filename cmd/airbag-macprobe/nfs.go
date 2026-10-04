package main

import (
	"net"
	"os"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	nfs "github.com/willscott/go-nfs"
	nfshelper "github.com/willscott/go-nfs/helpers"
)

// nfsServer exports dir over NFSv3 on a localhost port, as airbag would
// serve the workspace branch (AgentFS does the same).
type nfsServer struct{ l net.Listener }

func startNFS(dir string) (*nfsServer, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	h := nfshelper.NewNullAuthHandler(changeFS{osfs.New(dir)})
	go func() { _ = nfs.Serve(l, nfshelper.NewCachingHandler(h, 4096)) }()
	return &nfsServer{l: l}, nil
}

func (s *nfsServer) Port() int    { return s.l.Addr().(*net.TCPAddr).Port }
func (s *nfsServer) Close() error { return s.l.Close() }

// changeFS adds billy.Change (chmod, chown, chtimes) to an osfs, which
// go-nfs needs for SETATTR.
type changeFS struct{ billy.Filesystem }

func (c changeFS) path(name string) string { return c.Join(c.Root(), name) }

func (c changeFS) Chmod(name string, mode os.FileMode) error { return os.Chmod(c.path(name), mode) }
func (c changeFS) Lchown(name string, uid, gid int) error    { return os.Lchown(c.path(name), uid, gid) }
func (c changeFS) Chown(name string, uid, gid int) error     { return os.Chown(c.path(name), uid, gid) }
func (c changeFS) Chtimes(name string, atime, mtime time.Time) error {
	return os.Chtimes(c.path(name), atime, mtime)
}
