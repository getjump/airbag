//go:build linux

package policyfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/getjump/airbag/internal/runtimepolicy"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
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
