package review

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanTree(t *testing.T) {
	real, branch := t.TempDir(), t.TempDir()
	put := func(root, rel, data string, mode os.FileMode) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range []string{real, branch} {
		put(root, "same.txt", "same\n", 0o644)
		put(root, "edit.txt", "old\n", 0o644)
		put(root, "mode.sh", "#!/bin/sh\n", 0o644)
	}
	put(real, "gone.txt", "x", 0o644)
	put(real, "olddir/a/b.txt", "x", 0o644)
	put(real, "olddir/c.txt", "x", 0o644)
	put(branch, "edit.txt", "new\n", 0o644)
	_ = os.Chmod(filepath.Join(branch, "mode.sh"), 0o755)
	put(branch, "newdir/n.txt", "n", 0o644)
	_ = os.Symlink("same.txt", filepath.Join(branch, "link"))

	cs, err := ScanTree("ws", real, branch)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range cs {
		got[c.Rel] = c.Kind
	}
	want := map[string]string{
		"edit.txt": Modified, "mode.sh": Modified, "gone.txt": Deleted, "olddir": Deleted,
		"newdir": Added, "newdir/n.txt": Added, "link": Added,
	}
	if len(got) != len(want) {
		t.Errorf("changes = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
}
