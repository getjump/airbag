//go:build linux

package policyfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/runtimepolicy"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

func testRoot(t *testing.T, dir string, check func(runtimepolicy.Request) error) *node {
	t.Helper()
	v, err := Capture(dir, func(rs []runtimepolicy.Request) error {
		for _, r := range rs {
			if err := check(r); err != nil {
				return err
			}
		}
		return nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	root := &node{view: v}
	fs.NewNodeFS(root, &fs.Options{})
	return root
}
func TestPolicyOnExistingFilesAndMutations(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "upper"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	var observed []runtimepolicy.Request
	root := testRoot(t, dir, func(r runtimepolicy.Request) error {
		observed = append(observed, r)
		if r.Kind == "fs.write" || r.Kind == "fs.delete" {
			return syscall.EACCES
		}
		return nil
	})
	ctx := context.Background()
	var entry fuse.EntryOut
	inode, errno := root.Lookup(ctx, "upper", &entry)
	if errno != 0 {
		t.Fatal(errno)
	}
	root.AddChild("upper", inode, true)
	f, _, errno := inode.Operations().(*node).Open(ctx, syscall.O_WRONLY|syscall.O_TRUNC)
	if errno != syscall.EACCES || f != nil {
		t.Fatal("write bypassed policy", errno)
	}
	if e := root.Unlink(ctx, "upper"); e != syscall.EACCES {
		t.Fatal("delete bypassed", e)
	}
	if e := root.Rename(ctx, "upper", root, "renamed", 0); e != syscall.EACCES {
		t.Fatal("rename bypassed", e)
	}
	bytes, _ := os.ReadFile(filepath.Join(dir, "upper"))
	if string(bytes) != "original" {
		t.Fatal("denied operation changed backing file")
	}
	f, _, errno = inode.Operations().(*node).Open(ctx, syscall.O_RDONLY)
	if errno != 0 {
		t.Fatal(errno)
	}
	f.(fs.FileReleaser).Release(ctx)
	if len(observed) != 4 || observed[0].Target != filepath.Join(dir, "upper") {
		t.Fatalf("wrong observed attempts: %+v", observed)
	}
}
func TestBackingSymlinkSubstitutionCannotEscape(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	os.Mkdir(filepath.Join(dir, "parent"), 0700)
	os.WriteFile(filepath.Join(outside, "sentinel"), []byte("safe"), 0600)
	root := testRoot(t, dir, func(runtimepolicy.Request) error { return nil })
	ctx := context.Background()
	var entry fuse.EntryOut
	inode, e := root.Lookup(ctx, "parent", &entry)
	if e != 0 {
		t.Fatal(e)
	}
	root.AddChild("parent", inode, true)
	os.Remove(filepath.Join(dir, "parent"))
	os.Symlink(outside, filepath.Join(dir, "parent"))
	_, f, _, errno := inode.Operations().(*node).Create(ctx, "sentinel", syscall.O_WRONLY|syscall.O_TRUNC, 0600, &entry)
	if errno == 0 {
		f.(fs.FileReleaser).Release(ctx)
		t.Fatal("server followed replaced parent symlink")
	}
	bytes, _ := os.ReadFile(filepath.Join(outside, "sentinel"))
	if string(bytes) != "safe" {
		t.Fatal("changed outside captured view")
	}
	// Leaf substitution is also blocked, even when the FUSE inode is cached.
	os.Symlink(filepath.Join(outside, "sentinel"), filepath.Join(dir, "leaf"))
	leaf, e := root.Lookup(ctx, "leaf", &entry)
	if e != 0 {
		t.Fatal(e)
	}
	root.AddChild("leaf", leaf, true)
	if f, _, e := leaf.Operations().(*node).Open(ctx, syscall.O_WRONLY|syscall.O_TRUNC); e == 0 {
		f.(fs.FileReleaser).Release(ctx)
		t.Fatal("server followed leaf symlink")
	}
}

func TestLookupIdentityStableAndRenameKeepsIdentity(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "workspace"), 0700)
	os.WriteFile(filepath.Join(dir, "workspace", "file"), []byte("data"), 0600)
	root := testRoot(t, dir, func(runtimepolicy.Request) error { return nil })
	ctx := context.Background()
	var entry fuse.EntryOut
	a, e := root.Lookup(ctx, "workspace", &entry)
	if e != 0 {
		t.Fatal(e)
	}
	root.AddChild("workspace", a, true)
	b, e := root.Lookup(ctx, "workspace", &entry)
	if e != 0 || a.StableAttr().Ino != b.StableAttr().Ino {
		t.Fatal("mountpoint identity changed on revalidation")
	}
	file, e := a.Operations().(*node).Lookup(ctx, "file", &entry)
	if e != 0 {
		t.Fatal(e)
	}
	a.AddChild("file", file, true)
	if e := root.Rename(ctx, "workspace", root, "moved", 0); e != 0 {
		t.Fatal(e)
	}
	moved, e := root.Lookup(ctx, "moved", &entry)
	if e != 0 || moved.StableAttr().Ino != a.StableAttr().Ino {
		t.Fatal("renamed directory lost identity")
	}
	root.RmChild("workspace")
	root.AddChild("moved", moved, true)
	f, e := moved.Operations().(*node).Lookup(ctx, "file", &entry)
	if e != 0 || f.StableAttr().Ino != file.StableAttr().Ino {
		t.Fatal("renamed descendant lost identity")
	}
}

func TestIdentityTreeExchangeAndRemoval(t *testing.T) {
	v := &View{nextInode: 1 << 40}
	a := v.inode("a/sub/file", 1, 2)
	b := v.inode("b/file", 1, 3)
	unrelated := v.inode("unrelated/file", 1, 4)
	v.renamed("a", "b", true)
	if v.inode("b/sub/file", 1, 2) != a || v.inode("a/file", 1, 3) != b || v.inode("unrelated/file", 1, 4) != unrelated {
		t.Fatal("exchange damaged identities")
	}
	v.removed("b")
	if v.inode("b/sub/file", 1, 2) == a {
		t.Fatal("removed subtree kept stale identity")
	}
	// A directory entry on a mount may name the underlying mountpoint inode.
	// It must not change the identity previously learned from authoritative stat.
	id := v.inode("mount", 10, 20)
	v.inode("mount", 1, 99)
	if v.inode("mount", 10, 20) != id {
		t.Fatal("readdir changed mount identity")
	}
}

func TestLazyReaddirUsesPinnedDescriptor(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 600; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprint(i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	root := testRoot(t, dir, func(runtimepolicy.Request) error { return nil })
	stream, e := root.Readdir(context.Background())
	if e != 0 {
		t.Fatal(e)
	}
	defer stream.Close()
	if len(root.view.inodes.children) != 0 {
		t.Fatal("readdir eagerly populated every inode")
	}
	seen := map[string]bool{}
	for stream.HasNext() {
		entry, e := stream.Next()
		if e != 0 {
			t.Fatal(e)
		}
		if entry.Name == "." || entry.Name == ".." {
			continue
		}
		if entry.Mode&syscall.S_IFMT != syscall.S_IFREG || entry.Ino == 0 || seen[entry.Name] {
			t.Fatalf("invalid entry: %+v", entry)
		}
		seen[entry.Name] = true
	}
	if len(seen) != 600 {
		t.Fatalf("missing entries: %d", len(seen))
	}
}

func cacheTestRoot(t *testing.T, dir string, options Options, check Check, beforeRead BeforeRead) *node {
	t.Helper()
	v, err := CaptureWithOptions(dir, check, beforeRead, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	root := &node{view: v}
	fs.NewNodeFS(root, &fs.Options{})
	return root
}

func cacheTestChild(t *testing.T, root *node, name string) *node {
	t.Helper()
	var out fuse.EntryOut
	child, errno := root.Lookup(context.Background(), name, &out)
	if errno != 0 {
		t.Fatal(errno)
	}
	root.AddChild(name, child, true)
	return child.Operations().(*node)
}

func cacheTestOpen(t *testing.T, n *node, flags uint32) uint32 {
	t.Helper()
	f, fuseFlags, errno := n.Open(context.Background(), flags)
	if errno != 0 {
		t.Fatal(errno)
	}
	if _, unsafe := f.(fs.FilePassthroughFder); unsafe {
		t.Fatal("cache option exposed a passthrough backing fd")
	}
	if errno := f.(fs.FileReleaser).Release(context.Background()); errno != 0 {
		t.Fatal(errno)
	}
	return fuseFlags
}

func TestDataCacheRequiresKernelSeal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "readonly")
	if err := os.WriteFile(path, []byte("data"), 0444); err != nil {
		t.Fatal(err)
	}
	var observed []OperationStats
	root := cacheTestRoot(t, dir, Options{DataCache: CacheSealed, Observe: func(s OperationStats) {
		observed = append(observed, s)
	}}, func([]runtimepolicy.Request) error { return nil }, nil)
	n := cacheTestChild(t, root, "readonly")
	observed = nil
	for i := 0; i < 2; i++ {
		if flags := cacheTestOpen(t, n, syscall.O_RDONLY); flags&fuse.FOPEN_KEEP_CACHE != 0 {
			t.Fatal("read-only permissions were accepted as an immutable data seal")
		}
	}
	if len(observed) != 4 || observed[0].Operation != "gate" || observed[1].Operation != "open" || observed[1].CacheReason != "unsealed" {
		t.Fatalf("unexpected observation: %+v", observed)
	}
	if observed[0].Requests != 1 || observed[0].Errno != 0 || observed[1].Duration <= 0 {
		t.Fatalf("incomplete observation: %+v", observed)
	}
}

func TestDataSealIsIrreversible(t *testing.T) {
	fd, err := unix.MemfdCreate("policyfs-cache-test", unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if dataSealed(fd) {
		t.Fatal("unsealed memfd was accepted")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_WRITE); err != nil {
		t.Fatal(err)
	}
	if dataSealed(fd) {
		t.Fatal("memfd without grow/shrink seals was accepted")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		t.Fatal(err)
	}
	if !dataSealed(fd) {
		t.Fatal("fully sealed memfd was rejected")
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	n := &node{view: &View{options: Options{DataCache: CacheSealed}, sealProbe: dataSealed}, backing: backingKey{uint64(st.Dev), st.Ino}}
	if flags, reason := n.cacheOpenFlags(fd, syscall.O_RDONLY); flags != 0 || reason != "first" {
		t.Fatalf("first open preserved an unknown cache: %v %q", flags, reason)
	}
	if flags, reason := n.cacheOpenFlags(fd, syscall.O_RDONLY); flags != fuse.FOPEN_KEEP_CACHE || reason != "sealed-hit" {
		t.Fatalf("repeated sealed open missed cache: %v %q", flags, reason)
	}
	if _, err := unix.Pwrite(fd, []byte("evil"), 0); err != syscall.EPERM {
		t.Fatalf("sealed data was writable: %v", err)
	}
	if err := unix.Ftruncate(fd, 0); err != syscall.EPERM {
		t.Fatalf("sealed data was truncatable: %v", err)
	}
}

func TestDataCacheNeverSkipsPolicyOrBeforeRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	checks, taints, proofs := 0, 0, 0
	denyPolicy, denyRead := false, false
	root := cacheTestRoot(t, dir, Options{DataCache: CacheSealed}, func([]runtimepolicy.Request) error {
		checks++
		if denyPolicy {
			return syscall.EACCES
		}
		return nil
	}, func(path string, pid uint32, fd int) error {
		taints++
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil || st.Size != 4 {
			t.Fatal("beforeRead did not receive the opened backing file", err)
		}
		if denyRead {
			return syscall.EACCES
		}
		return nil
	})
	// Test the guard independently of an fs-verity-capable filesystem.
	root.view.sealProbe = func(int) bool { proofs++; return true }
	n := cacheTestChild(t, root, "file")
	if flags := cacheTestOpen(t, n, syscall.O_RDONLY); flags != 0 {
		t.Fatal("first open kept the cache")
	}
	if flags := cacheTestOpen(t, n, syscall.O_RDONLY); flags != fuse.FOPEN_KEEP_CACHE {
		t.Fatal("validated repeated open did not keep the cache")
	}
	denyRead = true
	f, flags, errno := n.Open(context.Background(), syscall.O_RDONLY)
	if f != nil || flags != 0 || errno != syscall.EACCES || proofs != 2 {
		t.Fatal("cache hit bypassed the pre-read barrier", f, flags, errno, proofs)
	}
	denyPolicy = true
	f, flags, errno = n.Open(context.Background(), syscall.O_RDONLY)
	if f != nil || flags != 0 || errno != syscall.EACCES || taints != 3 || checks != 4 {
		t.Fatal("cache hit bypassed policy", f, flags, errno, taints, checks)
	}
}

func TestDataCacheRejectsReplacementAndBackingMutation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	root := cacheTestRoot(t, dir, Options{DataCache: CacheSealed}, func([]runtimepolicy.Request) error { return nil }, nil)
	root.view.sealProbe = func(int) bool { return true }
	n := cacheTestChild(t, root, "file")
	cacheTestOpen(t, n, syscall.O_RDONLY)
	if cacheTestOpen(t, n, syscall.O_RDONLY) != fuse.FOPEN_KEEP_CACHE {
		t.Fatal("expected a repeated-open hit")
	}
	old, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Restore mtime after a same-size rewrite. The ctime guard must still
	// detect the mutation; this simulates a defensive fallback, since real
	// fs-verity/sealed backing inodes cannot be rewritten at all.
	time.Sleep(time.Millisecond)
	if err := os.WriteFile(path, []byte("evil"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, old.ModTime(), old.ModTime()); err != nil {
		t.Fatal(err)
	}
	if cacheTestOpen(t, n, syscall.O_RDONLY) != 0 {
		t.Fatal("same-size rewrite with restored mtime retained stale data")
	}
	if cacheTestOpen(t, n, syscall.O_RDONLY) != fuse.FOPEN_KEEP_CACHE {
		t.Fatal("unchanged new version missed cache")
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("new!"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if cacheTestOpen(t, n, syscall.O_RDONLY) != 0 {
			t.Fatal("a stale FUSE inode retained replacement data")
		}
	}
	newNode := cacheTestChild(t, root, "file")
	if newNode == n || newNode.StableAttr().Ino == n.StableAttr().Ino {
		t.Fatal("replacement reused the old FUSE identity")
	}
	cacheTestOpen(t, newNode, syscall.O_RDONLY)
	if cacheTestOpen(t, newNode, syscall.O_RDONLY) != fuse.FOPEN_KEEP_CACHE {
		t.Fatal("fresh replacement node missed cache")
	}
}

func TestDataCacheHardlinkAliasesAndWritableOpen(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Fatal(err)
	}
	root := cacheTestRoot(t, dir, Options{DataCache: CacheSealed}, func([]runtimepolicy.Request) error { return nil }, nil)
	root.view.sealProbe = func(int) bool { return true }
	left, right := cacheTestChild(t, root, "a"), cacheTestChild(t, root, "b")
	if left.backing != right.backing || left.StableAttr().Ino == right.StableAttr().Ino {
		t.Fatal("aliases lost their shared backing or distinct policy identity")
	}
	for _, n := range []*node{left, right} {
		cacheTestOpen(t, n, syscall.O_RDONLY)
		if cacheTestOpen(t, n, syscall.O_RDONLY) != fuse.FOPEN_KEEP_CACHE {
			t.Fatal("unchanged alias missed cache")
		}
	}
	if cacheTestOpen(t, left, syscall.O_WRONLY) != 0 || cacheTestOpen(t, left, syscall.O_RDONLY) != 0 {
		t.Fatal("writable open preserved a cache record")
	}
	time.Sleep(time.Millisecond)
	if err := os.WriteFile(a, []byte("evil"), 0600); err != nil {
		t.Fatal(err)
	}
	if cacheTestOpen(t, right, syscall.O_RDONLY) != 0 {
		t.Fatal("alias mutation retained the other FUSE inode's stale data")
	}
}

func TestCaptureOptionsAndIOObservations(t *testing.T) {
	dir := t.TempDir()
	for _, options := range []Options{{DataCache: "unsafe"}, {MetadataTTL: -time.Second}} {
		if v, err := CaptureWithOptions(dir, nil, nil, options); err == nil {
			v.Close()
			t.Fatal("invalid options were accepted", options)
		}
	}
	v, err := Capture(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v.options.DataCache != CacheDisabled || v.options.MetadataTTL != 100*time.Millisecond || !v.observedStart().IsZero() {
		t.Fatal("default settings changed or nil observer read the clock")
	}
	v.Close()
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	var observed []OperationStats
	root := cacheTestRoot(t, dir, Options{MetadataTTL: time.Second, Observe: func(s OperationStats) {
		observed = append(observed, s)
	}}, func([]runtimepolicy.Request) error { return nil }, nil)
	if root.view.options.MetadataTTL != time.Second {
		t.Fatal("custom metadata timeout was ignored")
	}
	n := cacheTestChild(t, root, "file")
	observed = nil
	f, flags, errno := n.Open(context.Background(), syscall.O_RDWR)
	if errno != 0 || flags != 0 {
		t.Fatal(errno, flags)
	}
	defer f.(fs.FileReleaser).Release(context.Background())
	result, errno := f.(fs.FileReader).Read(context.Background(), make([]byte, 4), 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	data, status := result.Bytes(make([]byte, 4))
	result.Done()
	if status != fuse.OK || string(data) != "data" {
		t.Fatal("observer changed fd-backed reads", status, string(data))
	}
	count, errno := f.(fs.FileWriter).Write(context.Background(), []byte("new!"), 0)
	if errno != 0 || count != 4 {
		t.Fatal(errno, count)
	}
	if len(observed) != 4 || observed[0].Requests != 2 || observed[1].CacheReason != "disabled" || observed[2].Operation != "read" || observed[3].Operation != "write" {
		t.Fatalf("missing callback observations: %+v", observed)
	}
}

func TestMetadataCallbackObservationsIncludeErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	var observed []OperationStats
	root := cacheTestRoot(t, dir, Options{Observe: func(s OperationStats) {
		observed = append(observed, s)
	}}, func([]runtimepolicy.Request) error { return nil }, nil)
	ctx := context.Background()
	n := cacheTestChild(t, root, "file")
	var attrs fuse.AttrOut
	if errno := n.Getattr(ctx, nil, &attrs); errno != 0 || attrs.Size != 4 {
		t.Fatal(errno, attrs.Size)
	}
	var entry fuse.EntryOut
	if _, errno := root.Lookup(ctx, "missing", &entry); errno != syscall.ENOENT {
		t.Fatal(errno)
	}
	stream, errno := root.Readdir(ctx)
	if errno != 0 {
		t.Fatal(errno)
	}
	for stream.HasNext() {
		if _, errno := stream.Next(); errno != 0 {
			t.Fatal(errno)
		}
	}
	stream.Close()
	link := cacheTestChild(t, root, "link")
	if target, errno := link.Readlink(ctx); errno != 0 || string(target) != "file" {
		t.Fatal(errno, string(target))
	}
	child, handle, _, errno := root.Create(ctx, "created", syscall.O_WRONLY, 0600, &entry)
	if errno != 0 {
		t.Fatal(errno)
	}
	root.AddChild("created", child, true)
	if errno := child.Operations().(*node).Setattr(ctx, handle, &fuse.SetAttrIn{SetAttrInCommon: fuse.SetAttrInCommon{Valid: fuse.FATTR_MODE, Mode: 0400}}, &attrs); errno != 0 {
		t.Fatal(errno)
	}
	handle.(fs.FileReleaser).Release(ctx)
	if errno := root.Rename(ctx, "created", root, "renamed", 0); errno != 0 {
		t.Fatal(errno)
	}
	if errno := root.Unlink(ctx, "renamed"); errno != 0 {
		t.Fatal(errno)
	}
	seen := make(map[string]int)
	lookupError := false
	for _, s := range observed {
		seen[s.Operation]++
		if s.Operation == "lookup" && s.Errno == syscall.ENOENT {
			lookupError = true
		}
	}
	for _, op := range []string{"lookup", "getattr", "readdir", "getdents", "readlink", "create", "setattr", "rename", "unlink"} {
		if seen[op] == 0 {
			t.Fatal("missing observed callback", op, seen)
		}
	}
	if !lookupError {
		t.Fatal("failed metadata callback was reported as success")
	}
}
