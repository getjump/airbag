package term

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// airbag escapes bidirectional controls in what it shows ("Trojan
// Source"); its own source must not carry them raw either, where they
// could make code read differently from what it does. Written as an
// escape (a backslash, u and the code point) a control is fine; the
// raw rune is not.
func TestNoRawBidiInSource(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Skip(err)
	}
	text := map[string]bool{".go": true, ".md": true, ".sh": true, ".yml": true, ".yaml": true, ".nix": true, ".py": true}
	checked := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "node_modules" || n == ".claude" {
				return filepath.SkipDir
			}
			return nil
		}
		// A symlink is not this module's source, and a dangling one (an
		// editor's lock file) cannot be read.
		if !text[filepath.Ext(p)] || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		b, err := os.ReadFile(p) //nolint:gosec // reads this module's own source tree
		if err != nil {
			return err
		}
		checked++
		for i, line := range strings.Split(string(b), "\n") {
			for _, r := range line {
				if bidi(r) {
					rel, _ := filepath.Rel(root, p)
					t.Errorf("%s:%d: raw bidirectional control %U; write it as an escape", rel, i+1, r)
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no source files found to check")
	}
}

func moduleRoot() (string, error) {
	d, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", os.ErrNotExist
		}
		d = parent
	}
}
