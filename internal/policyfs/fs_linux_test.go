//go:build linux

package policyfs

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/getjump/airbag/internal/runtimepolicy"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func testRoot(t *testing.T, dir string, check Check) *node {
	t.Helper()
	v, err := Capture(dir, check, nil)
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
