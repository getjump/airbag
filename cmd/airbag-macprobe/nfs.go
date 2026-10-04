package main

import (
	"net"
	"os"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
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
	h := nfshelper.NewNullAuthHandler(exportFS(dir))
	go func() { _ = nfs.Serve(l, nfshelper.NewCachingHandler(h, 4096)) }()
	return &nfsServer{l: l}, nil
}

func (s *nfsServer) Port() int    { return s.l.Addr().(*net.TCPAddr).Port }
func (s *nfsServer) Close() error { return s.l.Close() }

// exportFS is what the server exports: dir and nothing outside it, for
// any NFS client on this Mac (the server takes any local connection for
// the run). go-billy's BoundOS resolves every path, symlinks included,
// inside dir; its default ChrootOS can be escaped (GHSA-qw64-3x98-g7q2),
// and the fixed v5.9 needs Go 1.25.
func exportFS(dir string) billy.Filesystem {
	return changeFS{osfs.New(dir, osfs.WithBoundOS())}
}

// changeFS adds billy.Change (chmod, chown, chtimes), which go-nfs needs
// for SETATTR, held inside the root the same way.
type changeFS struct{ billy.Filesystem }

func (c changeFS) path(name string) (string, error) { return securejoin.SecureJoin(c.Root(), name) }

func (c changeFS) Chmod(name string, mode os.FileMode) error {
	p, err := c.path(name)
	if err != nil {
		return err
	}
	return os.Chmod(p, mode)
}

func (c changeFS) Lchown(name string, uid, gid int) error {
	p, err := c.path(name)
	if err != nil {
		return err
	}
	return os.Lchown(p, uid, gid)
}

func (c changeFS) Chown(name string, uid, gid int) error {
	p, err := c.path(name)
	if err != nil {
		return err
	}
	return os.Chown(p, uid, gid)
}

func (c changeFS) Chtimes(name string, atime, mtime time.Time) error {
	p, err := c.path(name)
	if err != nil {
		return err
	}
	return os.Chtimes(p, atime, mtime)
}
