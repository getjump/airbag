package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-billy/v5/osfs"
	nfs "github.com/willscott/go-nfs"
	nfshelper "github.com/willscott/go-nfs/helpers"
)

// nfsServer exports dir over NFSv3 on a localhost port, as airbag would
// serve the workspace branch (AgentFS does the same). It grants one
// mount, on a random path, to the probe's own mount_nfs and refuses
// every other mount request (mountGate). Seal stops it taking new
// connections once that mount is up; Close also ends every connection
// it took.
type nfsServer struct {
	l    *connListener
	gate *mountGate
}

func startNFS(dir string) (*nfsServer, error) {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &nfsServer{
		l:    &connListener{Listener: l, conns: map[*trackedConn]struct{}{}},
		gate: &mountGate{Handler: nfshelper.NewNullAuthHandler(exportFS(dir)), refused: memfs.New()},
	}
	go func() { _ = nfs.Serve(s.l, nfshelper.NewCachingHandler(s.gate, 4096)) }()
	return s, nil
}

func (s *nfsServer) Port() int { return s.l.Addr().(*net.TCPAddr).Port }

// Arm returns a new random export path for the next mount_nfs. The
// server grants it to the first MOUNT request that names it, once; the
// path of an earlier Arm is no longer granted. After a grant Arm fails:
// the export goes out once in the server's life, so a mount attempt
// that was granted it and did not come up is the last one.
func (s *nfsServer) Arm() (string, error) { return s.gate.arm() }

// Refused counts the MOUNT requests the server refused: those that
// named the armed path after its grant (late), and the rest (other).
func (s *nfsServer) Refused() (late, other int) { return s.gate.counts() }

// Seal stops taking new connections; the ones already open go on, the
// mount's among them. It is for after the probe's mount is up: the one
// grant has gone to it, so the other connections taken before Seal get
// no mount.
func (s *nfsServer) Seal() { _ = s.l.Listener.Close() }

// Close stops taking connections, ends every connection the server
// took and grants no mount after it. When the probe's own mount does
// not come up, it leaves no other client a session.
func (s *nfsServer) Close() error {
	s.gate.disarm()
	return s.l.closeAll()
}

// mountGate grants the export to one MOUNT request: the first that
// names the armed path, with at most one trailing "/" (the random part
// is what has to match). Every other request gets an access error, and
// an empty in-memory filesystem rather than nil: go-nfs makes a root
// handle even for a refused mount (it does not send it), and a nil
// filesystem would crash the probe there. The refusals are counted, not
// their paths.
type mountGate struct {
	nfs.Handler
	refused billy.Filesystem

	mu      sync.Mutex
	path    []byte // the armed path; nil when none is
	granted bool   // the one grant has gone
	late    int    // refused: named the armed path after its grant
	other   int    // refused: named another path, or no path was armed
}

func (g *mountGate) arm() (string, error) {
	p := "/" + rand.Text() // 128 random bits
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.granted {
		return "", errors.New("the export was granted to an earlier mount request, and the server grants it once")
	}
	g.path = []byte(p)
	return p, nil
}

func (g *mountGate) disarm() {
	g.mu.Lock()
	g.path = nil
	g.mu.Unlock()
}

func (g *mountGate) counts() (late, other int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.late, g.other
}

func (g *mountGate) Mount(ctx context.Context, c net.Conn, req nfs.MountRequest) (nfs.MountStatus, billy.Filesystem, []nfs.AuthFlavor) {
	g.mu.Lock()
	named := g.path != nil && namesPath(req.Dirpath, g.path)
	ok := named && !g.granted
	switch {
	case ok:
		g.granted = true
	case named:
		g.late++
	default:
		g.other++
	}
	g.mu.Unlock()
	if !ok {
		return nfs.MountStatusErrAcces, g.refused, nil
	}
	return g.Handler.Mount(ctx, c, req)
}

// namesPath reports whether dirpath is p, or p and one "/".
func namesPath(dirpath, p []byte) bool {
	if n := len(dirpath); n == len(p)+1 && dirpath[n-1] == '/' {
		dirpath = dirpath[:n-1]
	}
	return subtle.ConstantTimeCompare(dirpath, p) == 1
}

// connListener keeps the connections it accepted, so that closeAll can
// end them: closing a listener leaves its open connections running.
type connListener struct {
	net.Listener
	mu     sync.Mutex
	conns  map[*trackedConn]struct{}
	closed bool
}

func (l *connListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed { // accepted while closeAll ran
		c.Close()
		return nil, net.ErrClosed
	}
	tc := &trackedConn{Conn: c, l: l}
	l.conns[tc] = struct{}{}
	return tc, nil
}

// closeAll closes the listener and every connection it accepted.
func (l *connListener) closeAll() error {
	l.mu.Lock()
	l.closed = true
	conns := l.conns
	l.conns = nil
	l.mu.Unlock()
	err := l.Listener.Close()
	for c := range conns {
		_ = c.Conn.Close()
	}
	return err
}

// trackedConn leaves its listener's set when it is closed.
type trackedConn struct {
	net.Conn
	l *connListener
}

func (c *trackedConn) Close() error {
	c.l.mu.Lock()
	delete(c.l.conns, c)
	c.l.mu.Unlock()
	return c.Conn.Close()
}

// exportFS is what the server exports: dir and nothing outside it.
// go-billy's BoundOS resolves every path, symlinks included, inside dir
// (v5.9 also fixes the ChrootOS escape, GHSA-qw64-3x98-g7q2; BoundOS is
// the backend the advisory recommends). BoundOS resolves a path and then
// uses it, so a client that swaps a symlink in between could still reach
// outside.
// The one client granted the export is the probe's own mount (see
// mountGate), unless a local process reads the armed path from the
// process list while mount_nfs runs and mounts first; then the probe's
// mount fails, and N1 fails and closes the server and its connections.
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
