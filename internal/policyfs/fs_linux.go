//go:build linux

// Package policyfs gates filesystem entry points above a completed sandbox
// view. Backing access is descriptor-relative; directory symlinks and magic
// links cannot redirect the privileged server outside that captured view.
package policyfs

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/getjump/airbag/internal/runtimepolicy"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

type Check func([]runtimepolicy.Request) error
type BeforeRead func(path string, pid uint32, fd int) error

type CacheMode string

const (
	CacheDisabled CacheMode = "off"
	// CacheSealed retains data only when the backing inode is protected by
	// fs-verity or irreversible memfd seals. Read-only permissions and mounts
	// do not qualify: another hardlink or mount could still modify their data.
	CacheSealed CacheMode = "sealed"
)

// OperationStats observes callback work, not an operation's eventual success
// in the caller. In particular, Read returns a fd-backed ReadResult: copying
// its bytes into the kernel happens after the callback has returned.
type OperationStats struct {
	Operation   string
	Duration    time.Duration
	Requests    int
	Errno       syscall.Errno
	CacheKeep   bool
	CacheReason string
}

type Options struct {
	DataCache CacheMode
	// Zero selects the normal 100ms metadata timeout. This is unrelated to
	// data caching, and never caches policy decisions.
	MetadataTTL time.Duration
	// Observe is synchronous and must be concurrency-safe. With a nil hook,
	// operation timings do not call time.Now.
	Observe func(OperationStats)
}

type backingKey struct{ dev, ino uint64 }
type inodeTree struct {
	children   map[string]*inodeTree
	identities map[backingKey]uint64
}

func (t *inodeTree) child(name string, create bool) *inodeTree {
	if t.children == nil && create {
		t.children = make(map[string]*inodeTree)
	}
	if t.children[name] == nil && create {
		t.children[name] = &inodeTree{}
	}
	return t.children[name]
}
func (t *inodeTree) path(rel string, create bool) *inodeTree {
	if rel == "." {
		return t
	}
	for _, name := range strings.Split(rel, "/") {
		t = t.child(name, create)
		if t == nil {
			return nil
		}
	}
	return t
}

type View struct {
	mu         sync.Mutex
	inodes     inodeTree
	nextInode  uint64
	fd         int
	path       string
	check      Check
	beforeRead BeforeRead
	options    Options
	// sealProbe is private so a caller cannot assert that a mutable inode is
	// sealed. Unit tests can exercise version guards on ordinary files.
	sealProbe func(int) bool
}

// Capture must precede all overmounts, including the HOME mount when the
// workspace is a child of HOME. The retained fd is never inherited by agents.
func Capture(path string, check Check, beforeRead BeforeRead) (*View, error) {
	return CaptureWithOptions(path, check, beforeRead, Options{})
}

func CaptureWithOptions(path string, check Check, beforeRead BeforeRead, options Options) (*View, error) {
	if options.DataCache == "" {
		options.DataCache = CacheDisabled
	}
	if options.DataCache != CacheDisabled && options.DataCache != CacheSealed {
		return nil, fmt.Errorf("unsupported filesystem data cache mode %q", options.DataCache)
	}
	if options.MetadataTTL < 0 {
		return nil, fmt.Errorf("negative filesystem metadata timeout")
	}
	if options.MetadataTTL == 0 {
		options.MetadataTTL = 100 * time.Millisecond
	}
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &View{fd: fd, path: filepath.Clean(path), check: check, beforeRead: beforeRead, nextInode: 1 << 40, options: options, sealProbe: dataSealed}, nil
}

func (v *View) observedStart() time.Time {
	if v.options.Observe != nil {
		return time.Now()
	}
	return time.Time{}
}
func (v *View) observedEnd(start time.Time, stats OperationStats) {
	if v.options.Observe != nil {
		stats.Duration = time.Since(start)
		v.options.Observe(stats)
	}
}
func (v *View) observedErrnoEnd(start time.Time, operation string, errno *syscall.Errno) {
	v.observedEnd(start, OperationStats{Operation: operation, Errno: *errno})
}

// Stable identities are essential: dentry revalidation must not detach the
// workspace mount nested inside the HOME filesystem. Keep hardlink aliases
// distinct without changing an unchanged path's inode on every lookup.
func (v *View) inode(rel string, dev, ino uint64) uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	t := v.inodes.path(rel, true)
	key := backingKey{dev, ino}
	if id := t.identities[key]; id != 0 {
		return id
	}
	if t.identities == nil {
		t.identities = make(map[backingKey]uint64)
	}
	v.nextInode++
	t.identities[key] = v.nextInode
	return v.nextInode
}

// Move the identity subtree by its parent links: O(path depth), independent of
// the number of unrelated files or descendants. Keep aliases path-specific.
func (v *View) renamed(src, dst string, exchange bool) {
	if src == dst {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	a := v.inodes.path(filepath.Dir(src), true)
	b := v.inodes.path(filepath.Dir(dst), true)
	x, y := a.child(filepath.Base(src), false), b.child(filepath.Base(dst), false)
	delete(a.children, filepath.Base(src))
	delete(b.children, filepath.Base(dst))
	if x != nil {
		b.child(filepath.Base(dst), true)
		b.children[filepath.Base(dst)] = x
	}
	if exchange && y != nil {
		a.child(filepath.Base(src), true)
		a.children[filepath.Base(src)] = y
	}
}
func (v *View) removed(rel string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if p := v.inodes.path(filepath.Dir(rel), false); p != nil {
		delete(p.children, filepath.Base(rel))
	}
}

func (v *View) Close() error { return unix.Close(v.fd) }

// closeFD closes a backing descriptor the server opened for one request;
// nothing was written through it that a failed close could lose.
func closeFD(fd int) { _ = unix.Close(fd) }

func (v *View) Mount() (*fuse.Server, error) {
	zero := time.Duration(0)
	metadataTTL := v.options.MetadataTTL
	server, err := fs.Mount(v.path, &node{view: v}, &fs.Options{
		MountOptions: fuse.MountOptions{DirectMount: true, DirectMountStrict: true, FsName: "airbag-policy", Name: "airbag", Options: []string{"default_permissions"}, EnableLocks: true},
		AttrTimeout:  &metadataTTL, EntryTimeout: &metadataTTL, NegativeTimeout: &zero,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", v.path, err)
	}
	return server, nil
}

type node struct {
	fs.Inode
	view     *View
	backing  backingKey
	cacheMu  sync.Mutex
	cache    backingVersion
	hasCache bool
}

func (n *node) rel() string {
	p := n.Path(n.Root())
	if p == "" {
		return "."
	}
	return p
}
func (n *node) child(name string) string   { return filepath.Join(n.rel(), name) }
func (n *node) absolute(rel string) string { return filepath.Join(n.view.path, rel) }
func callerPID(ctx context.Context) uint32 {
	c, ok := fuse.FromContext(ctx)
	if !ok {
		return 0
	}
	return c.Pid
}
func (n *node) request(ctx context.Context, rel, kind, detail string) runtimepolicy.Request {
	return runtimepolicy.Request{Source: "fuse", Kind: kind, Target: n.absolute(rel), Detail: detail, PID: callerPID(ctx)}
}
func (n *node) gates(requests []runtimepolicy.Request) (errno syscall.Errno) {
	start := n.view.observedStart()
	defer func() {
		n.view.observedEnd(start, OperationStats{Operation: "gate", Requests: len(requests), Errno: errno})
	}()
	if n.view.check == nil {
		return syscall.EACCES
	}
	if err := n.view.check(requests); err != nil {
		return syscall.EACCES
	}
	return 0
}
func (n *node) gate(ctx context.Context, rel, kind, detail string) syscall.Errno {
	return n.gates([]runtimepolicy.Request{n.request(ctx, rel, kind, detail)})
}

func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}
func (v *View) dir(rel string) (int, error) {
	return unix.Openat2(v.fd, rel, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
}
func (n *node) parent(rel string) (int, string, error) {
	base := filepath.Base(rel)
	if rel == "." {
		base = "."
	}
	if base != "." && !validName(base) {
		return -1, "", syscall.EINVAL
	}
	fd, err := n.view.dir(filepath.Dir(rel))
	return fd, base, err
}
func (n *node) stat(rel string, st *syscall.Stat_t) syscall.Errno {
	fd, name, err := n.parent(rel)
	if err != nil {
		return fs.ToErrno(err)
	}
	defer closeFD(fd)
	// syscall and unix Stat_t have the same Linux layout, but avoid unsafe casts.
	f, err := unix.Openat(fd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fs.ToErrno(err)
	}
	defer closeFD(f)
	return fs.ToErrno(syscall.Fstat(f, st))
}
func (n *node) newChild(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	var st syscall.Stat_t
	if errno := n.stat(n.child(name), &st); errno != 0 {
		return nil, errno
	}
	out.Attr.FromStat(&st)
	// Give aliases distinct nodes: a path policy must not inherit the first
	// hardlink's pathname through inode deduplication. See documented limits.
	ch := n.NewInode(ctx, &node{view: n.view, backing: backingKey{st.Dev, st.Ino}}, fs.StableAttr{Mode: st.Mode, Ino: n.view.inode(n.child(name), st.Dev, st.Ino)})
	return ch, 0
}
func (n *node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (child *fs.Inode, errno syscall.Errno) {
	defer n.view.observedErrnoEnd(n.view.observedStart(), "lookup", &errno)
	if !validName(name) {
		return nil, syscall.EINVAL
	}
	return n.newChild(ctx, name, out)
}
func (n *node) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) (errno syscall.Errno) {
	defer n.view.observedErrnoEnd(n.view.observedStart(), "getattr", &errno)
	if f, ok := fh.(fs.FileGetattrer); ok {
		return f.Getattr(ctx, out)
	}
	var st syscall.Stat_t
	errno = n.stat(n.rel(), &st)
	if errno == 0 {
		out.FromStat(&st)
	}
	return errno
}
func (n *node) Readdir(ctx context.Context) (stream fs.DirStream, errno syscall.Errno) {
	// Readdir opens a lazy stream; getdents below observes its actual directory
	// reads separately, rather than claiming they happened in this callback.
	defer n.view.observedErrnoEnd(n.view.observedStart(), "readdir", &errno)
	rel := n.rel()
	if e := n.gate(ctx, rel, "fs.read", "readdir"); e != 0 {
		return nil, e
	}
	fd, err := unix.Openat2(n.view.fd, rel, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		closeFD(fd)
		return nil, fs.ToErrno(err)
	}
	return &dirStream{fd: fd, view: n.view, rel: rel, dev: st.Dev, buf: make([]byte, 8192)}, 0
}

// getdents supplies names, types and backing inode numbers without one stat per
// child. Lookup still fetches authoritative attributes (including mount roots).
// The descriptor is CLOEXEC and is pinned inside the captured view.
type dirStream struct {
	fd        int
	view      *View
	rel       string
	dev       uint64
	buf, todo []byte
	errno     syscall.Errno
	eof       bool
}

func (d *dirStream) HasNext() bool {
	if len(d.todo) == 0 && d.errno == 0 && !d.eof {
		start := d.view.observedStart()
		n, err := unix.Getdents(d.fd, d.buf)
		d.errno = fs.ToErrno(err)
		d.view.observedEnd(start, OperationStats{Operation: "getdents", Errno: d.errno})
		if n > 0 {
			d.todo = d.buf[:n]
		} else {
			d.eof = true
		}
	}
	return len(d.todo) != 0 || d.errno != 0
}
func (d *dirStream) Next() (fuse.DirEntry, syscall.Errno) {
	if !d.HasNext() {
		return fuse.DirEntry{}, 0
	}
	if d.errno != 0 {
		e := d.errno
		d.errno = 0
		return fuse.DirEntry{}, e
	}
	var entry fuse.DirEntry
	n := entry.Parse(d.todo)
	if n <= 0 || n > len(d.todo) {
		d.eof = true
		d.todo = nil
		return entry, syscall.EIO
	}
	d.todo = d.todo[n:]
	entry.Ino = d.view.inode(filepath.Join(d.rel, entry.Name), d.dev, entry.Ino)
	return entry, 0
}
func (d *dirStream) Close() {
	if d.fd >= 0 {
		closeFD(d.fd)
		d.fd = -1
	}
	d.eof = true
	d.todo = nil
}

func (n *node) Readlink(ctx context.Context) (target []byte, errno syscall.Errno) {
	defer n.view.observedErrnoEnd(n.view.observedStart(), "readlink", &errno)
	rel := n.rel()
	if e := n.gate(ctx, rel, "fs.read", "readlink"); e != 0 {
		return nil, e
	}
	fd, name, err := n.parent(rel)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer closeFD(fd)
	buf := make([]byte, 4096)
	count, err := unix.Readlinkat(fd, name, buf)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return buf[:count], 0
}
func (n *node) openChecks(ctx context.Context, rel string, flags uint32) []runtimepolicy.Request {
	var requests []runtimepolicy.Request
	if flags&syscall.O_ACCMODE != syscall.O_WRONLY {
		requests = append(requests, n.request(ctx, rel, "fs.read", "open"))
	}
	if flags&syscall.O_ACCMODE != syscall.O_RDONLY || flags&(syscall.O_TRUNC|syscall.O_CREAT) != 0 {
		requests = append(requests, n.request(ctx, rel, "fs.write", "open"))
	}
	return requests
}

// The version guard describes the actually opened backing descriptor, never a
// pathname stat. Even sealed data may be replaced or the inode's metadata may
// change, so immutability alone is insufficient to retain this FUSE inode's
// cache. A stale FUSE node opening a replacement must always discard its cache.
type backingVersion struct {
	key          backingKey
	size         int64
	mtime, ctime syscall.Timespec
}

func dataSealed(fd int) bool {
	if flags, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS); err == nil && flags&unix.FS_VERITY_FL != 0 {
		return true
	}
	const required = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	return err == nil && seals&required == required
}

func (n *node) cacheOpenFlags(fd int, flags uint32) (uint32, string) {
	if n.view.options.DataCache != CacheSealed {
		return 0, "disabled"
	}
	n.cacheMu.Lock()
	defer n.cacheMu.Unlock()
	clear := func(reason string) (uint32, string) {
		n.hasCache = false
		return 0, reason
	}
	if flags&syscall.O_ACCMODE != syscall.O_RDONLY || flags&(syscall.O_TRUNC|syscall.O_CREAT) != 0 {
		return clear("writable")
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return clear("stat-error")
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return clear("not-regular")
	}
	if key := (backingKey{st.Dev, st.Ino}); key != n.backing {
		return clear("identity-changed")
	}
	if !n.view.sealProbe(fd) {
		return clear("unsealed")
	}
	// The seal is irreversible. Validate the complete version after obtaining
	// its proof, so a pre-seal modification cannot populate a later hit.
	if err := syscall.Fstat(fd, &st); err != nil {
		return clear("stat-error")
	}
	version := backingVersion{backingKey{st.Dev, st.Ino}, st.Size, st.Mtim, st.Ctim}
	if n.hasCache && n.cache == version {
		return fuse.FOPEN_KEEP_CACHE, "sealed-hit"
	}
	reason := "first"
	if n.hasCache {
		reason = "version-changed"
	}
	n.cache, n.hasCache = version, true
	return 0, reason
}

func (n *node) open(ctx context.Context, rel string, flags uint32, mode uint32) (result fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	start := n.view.observedStart()
	cacheReason := "not-opened"
	defer func() {
		n.view.observedEnd(start, OperationStats{Operation: "open", Errno: errno, CacheKeep: fuseFlags&fuse.FOPEN_KEEP_CACHE != 0, CacheReason: cacheReason})
	}()
	fd, name, err := n.parent(rel)
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}
	defer closeFD(fd)
	backing, err := unix.Openat(fd, name, int(flags)|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}
	if flags&syscall.O_ACCMODE != syscall.O_WRONLY && n.view.beforeRead != nil {
		if err := n.view.beforeRead(n.absolute(rel), callerPID(ctx), backing); err != nil {
			closeFD(backing)
			cacheReason = "before-read-denied"
			return nil, 0, syscall.EACCES
		}
	}
	fuseFlags, cacheReason = n.cacheOpenFlags(backing, flags)
	return &file{base: fs.NewLoopbackFile(backing), view: n.view}, fuseFlags, 0
}
func (n *node) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	rel := n.rel()
	if e := n.gates(n.openChecks(ctx, rel, flags)); e != 0 {
		return nil, 0, e
	}
	return n.open(ctx, rel, flags, 0)
}
func (n *node) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *fs.Inode, handle fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	defer n.view.observedErrnoEnd(n.view.observedStart(), "create", &errno)
	if !validName(name) {
		return nil, nil, 0, syscall.EINVAL
	}
	rel := n.child(name)
	requests := n.openChecks(ctx, rel, flags|syscall.O_CREAT)
	if mode&0o111 != 0 {
		requests = append(requests, n.request(ctx, rel, "fs.exec_bit", "create"))
	}
	if e := n.gates(requests); e != 0 {
		return nil, nil, 0, e
	}
	f, _, e := n.open(ctx, rel, flags|syscall.O_CREAT, mode)
	if e != 0 {
		return nil, nil, 0, e
	}
	child, e := n.newChild(ctx, name, out)
	if e != 0 {
		_ = f.(fs.FileReleaser).Release(ctx)
		return nil, nil, 0, e
	}
	return child, f, 0, 0
}
func (n *node) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (inode *fs.Inode, errno syscall.Errno) {
	defer n.view.observedErrnoEnd(n.view.observedStart(), "mkdir", &errno)
	if !validName(name) {
		return nil, syscall.EINVAL
	}
	rel := n.child(name)
	if e := n.gate(ctx, rel, "fs.write", "mkdir"); e != 0 {
		return nil, e
	}
	fd, err := n.view.dir(n.rel())
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer closeFD(fd)
	if err := unix.Mkdirat(fd, name, mode); err != nil {
		return nil, fs.ToErrno(err)
	}
	return n.newChild(ctx, name, out)
}
func (n *node) Mknod(ctx context.Context, name string, mode uint32, dev uint32, out *fuse.EntryOut) (inode *fs.Inode, errno syscall.Errno) {
	defer n.view.observedErrnoEnd(n.view.observedStart(), "mknod", &errno)
	if !validName(name) {
		return nil, syscall.EINVAL
	}
	// Never let a privileged filesystem server create agent-controlled devices.
	switch mode & syscall.S_IFMT {
	case syscall.S_IFREG, syscall.S_IFIFO, syscall.S_IFSOCK:
	default:
		return nil, syscall.EPERM
	}
	if e := n.gate(ctx, n.child(name), "fs.write", "mknod"); e != 0 {
		return nil, e
	}
	fd, err := n.view.dir(n.rel())
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer closeFD(fd)
	if err := unix.Mknodat(fd, name, mode, int(dev)); err != nil {
		return nil, fs.ToErrno(err)
	}
	return n.newChild(ctx, name, out)
}
func (n *node) remove(ctx context.Context, name string, flags int) syscall.Errno {
	if !validName(name) {
		return syscall.EINVAL
	}
	detail := "unlink"
	if flags != 0 {
		detail = "rmdir"
	}
	if e := n.gate(ctx, n.child(name), "fs.delete", detail); e != 0 {
		return e
	}
	fd, err := n.view.dir(n.rel())
	if err != nil {
		return fs.ToErrno(err)
	}
	defer closeFD(fd)
	if err := unix.Unlinkat(fd, name, flags); err != nil {
		return fs.ToErrno(err)
	}
	n.view.removed(n.child(name))
	return 0
}
func (n *node) Unlink(ctx context.Context, name string) (errno syscall.Errno) {
	defer n.view.observedErrnoEnd(n.view.observedStart(), "unlink", &errno)
	return n.remove(ctx, name, 0)
}
func (n *node) Rmdir(ctx context.Context, name string) (errno syscall.Errno) {
	defer n.view.observedErrnoEnd(n.view.observedStart(), "rmdir", &errno)
	return n.remove(ctx, name, unix.AT_REMOVEDIR)
}
func (n *node) Rename(ctx context.Context, name string, newparent fs.InodeEmbedder, newname string, flags uint32) (errno syscall.Errno) {
	defer n.view.observedErrnoEnd(n.view.observedStart(), "rename", &errno)
	p, ok := newparent.(*node)
	if !ok || p.view != n.view {
		return syscall.EXDEV
	}
	if !validName(name) || !validName(newname) {
		return syscall.EINVAL
	}
	src, dst := n.child(name), p.child(newname)
	checks := [][3]string{{src, "fs.delete", "rename"}, {dst, "fs.write", "rename"}, {dst, "fs.delete", "rename-replace"}}
	if flags&unix.RENAME_EXCHANGE != 0 {
		checks = append(checks, [3]string{src, "fs.write", "rename-exchange"})
	}
	requests := make([]runtimepolicy.Request, 0, len(checks))
	for _, c := range checks {
		requests = append(requests, n.request(ctx, c[0], c[1], c[2]))
	}
	if e := n.gates(requests); e != 0 {
		return e
	}
	a, err := n.view.dir(n.rel())
	if err != nil {
		return fs.ToErrno(err)
	}
	defer closeFD(a)
	b, err := n.view.dir(p.rel())
	if err != nil {
		return fs.ToErrno(err)
	}
	defer closeFD(b)
	if err := unix.Renameat2(a, name, b, newname, uint(flags)); err != nil {
		return fs.ToErrno(err)
	}
	n.view.renamed(src, dst, flags&unix.RENAME_EXCHANGE != 0)
	return 0
}
func (n *node) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (inode *fs.Inode, errno syscall.Errno) {
	defer n.view.observedErrnoEnd(n.view.observedStart(), "symlink", &errno)
	if !validName(name) {
		return nil, syscall.EINVAL
	}
	if e := n.gate(ctx, n.child(name), "fs.write", "symlink"); e != 0 {
		return nil, e
	}
	fd, err := n.view.dir(n.rel())
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer closeFD(fd)
	if err := unix.Symlinkat(target, fd, name); err != nil {
		return nil, fs.ToErrno(err)
	}
	return n.newChild(ctx, name, out)
}
func (n *node) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (inode *fs.Inode, errno syscall.Errno) {
	defer n.view.observedErrnoEnd(n.view.observedStart(), "link", &errno)
	t, ok := target.(*node)
	if !ok || t.view != n.view {
		return nil, syscall.EXDEV
	}
	if !validName(name) {
		return nil, syscall.EINVAL
	}
	if e := n.gates([]runtimepolicy.Request{
		n.request(ctx, t.rel(), "fs.read", "link-source"),
		n.request(ctx, t.rel(), "fs.write", "link-source"),
		n.request(ctx, n.child(name), "fs.write", "link"),
	}); e != 0 {
		return nil, e
	}
	a, oldname, err := n.parent(t.rel())
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer closeFD(a)
	b, err := n.view.dir(n.rel())
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer closeFD(b)
	if err := unix.Linkat(a, oldname, b, name, 0); err != nil {
		return nil, fs.ToErrno(err)
	}
	return n.newChild(ctx, name, out)
}
func (n *node) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) (errno syscall.Errno) {
	defer n.view.observedErrnoEnd(n.view.observedStart(), "setattr", &errno)
	rel := n.rel()
	requests := []runtimepolicy.Request{n.request(ctx, rel, "fs.write", "setattr")}
	if mode, ok := in.GetMode(); ok && mode&0o111 != 0 {
		requests = append(requests, n.request(ctx, rel, "fs.exec_bit", "chmod"))
	}
	if e := n.gates(requests); e != 0 {
		return e
	}
	if f, ok := fh.(fs.FileSetattrer); ok {
		return f.Setattr(ctx, in, out)
	}
	// Metadata operations must still work on mode-000 files. Pin the leaf
	// with O_PATH before using our own /proc fd link; no pathname race can
	// redirect chmod/chown/timestamps to a replacement symlink.
	parent, name, err := n.parent(rel)
	if err != nil {
		return fs.ToErrno(err)
	}
	defer closeFD(parent)
	fd, err := unix.Openat(parent, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fs.ToErrno(err)
	}
	defer closeFD(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fs.ToErrno(err)
	}
	pinned := fmt.Sprintf("/proc/self/fd/%d", fd)
	if mode, ok := in.GetMode(); ok {
		if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			return syscall.EOPNOTSUPP
		}
		if err := unix.Chmod(pinned, mode); err != nil {
			return fs.ToErrno(err)
		}
	}
	uid, uok := in.GetUID()
	gid, gok := in.GetGID()
	if uok || gok {
		u, g := -1, -1
		if uok {
			u = int(uid)
		}
		if gok {
			g = int(gid)
		}
		if err := unix.Fchownat(fd, "", u, g, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fs.ToErrno(err)
		}
	}
	atime, aok := in.GetATime()
	mtime, mok := in.GetMTime()
	if aok || mok {
		times := []unix.Timespec{{Nsec: unix.UTIME_OMIT}, {Nsec: unix.UTIME_OMIT}}
		if aok {
			times[0] = unix.NsecToTimespec(atime.UnixNano())
		}
		if mok {
			times[1] = unix.NsecToTimespec(mtime.UnixNano())
		}
		if err := unix.UtimesNanoAt(fd, "", times, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fs.ToErrno(err)
		}
	}
	if size, ok := in.GetSize(); ok {
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			return syscall.EINVAL
		}
		if size > math.MaxInt64 {
			return syscall.EFBIG
		}
		// The pinned descriptor resolves to this inode, even after an unlink.
		writer, err := unix.Open(pinned, unix.O_WRONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fs.ToErrno(err)
		}
		err = unix.Ftruncate(writer, int64(size))
		closeFD(writer)
		if err != nil {
			return fs.ToErrno(err)
		}
	}
	if err := syscall.Fstat(fd, &st); err != nil {
		return fs.ToErrno(err)
	}
	out.FromStat(&st)
	return 0
}

// Unsupported xattrs and copy_file_range are refused by go-fuse, rather than
// forwarded through an unchecked path. Tools can use their normal fallbacks.
// Keeping the file wrapper explicit also prevents FUSE passthrough negotiation
// from handing the kernel an unguarded backing descriptor.
type file struct {
	base fs.FileHandle
	view *View
}

func (f *file) Read(ctx context.Context, b []byte, o int64) (result fuse.ReadResult, errno syscall.Errno) {
	start := f.view.observedStart()
	defer func() { f.view.observedEnd(start, OperationStats{Operation: "read", Errno: errno}) }()
	return f.base.(fs.FileReader).Read(ctx, b, o)
}
func (f *file) Write(ctx context.Context, b []byte, o int64) (count uint32, errno syscall.Errno) {
	start := f.view.observedStart()
	defer func() { f.view.observedEnd(start, OperationStats{Operation: "write", Errno: errno}) }()
	return f.base.(fs.FileWriter).Write(ctx, b, o)
}
func (f *file) Release(ctx context.Context) syscall.Errno {
	return f.base.(fs.FileReleaser).Release(ctx)
}
func (f *file) Flush(ctx context.Context) syscall.Errno { return f.base.(fs.FileFlusher).Flush(ctx) }
func (f *file) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	return f.base.(fs.FileFsyncer).Fsync(ctx, flags)
}
func (f *file) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	return f.base.(fs.FileGetattrer).Getattr(ctx, out)
}
func (f *file) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	return f.base.(fs.FileSetattrer).Setattr(ctx, in, out)
}
func (f *file) Allocate(ctx context.Context, off, size uint64, mode uint32) syscall.Errno {
	return f.base.(fs.FileAllocater).Allocate(ctx, off, size, mode)
}
func (f *file) Getlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	return f.base.(fs.FileGetlker).Getlk(ctx, owner, lk, flags, out)
}
func (f *file) Setlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	return f.base.(fs.FileSetlker).Setlk(ctx, owner, lk, flags)
}
func (f *file) Setlkw(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	return f.base.(fs.FileSetlkwer).Setlkw(ctx, owner, lk, flags)
}
func (f *file) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	return f.base.(fs.FileLseeker).Lseek(ctx, off, whence)
}

var _ fs.NodeRenamer = (*node)(nil)
