package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// makeTree writes n small files in a node_modules-like layout: packages
// of 25 files, each package nested two levels deep.
func makeTree(root string, n int) error {
	for i := 0; i < n; i++ {
		pkg := i / 25
		d := filepath.Join(root, "node_modules", fmt.Sprintf("pkg-%03d", pkg%200), fmt.Sprintf("v%d", pkg/200), "lib")
		if i%25 == 0 {
			if err := os.MkdirAll(d, 0o755); err != nil {
				return err
			}
		}
		body := fmt.Sprintf("module.exports = %d;\n", i)
		if err := os.WriteFile(filepath.Join(d, fmt.Sprintf("f%02d.js", i%25)), []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// countFiles walks root and counts regular files.
func countFiles(root string) (int, error) {
	n := 0
	err := filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			n++
		}
		return nil
	})
	return n, err
}

// resolve returns the real path, as Seatbelt matches it
// (/var/folders/... is /private/var/folders/...).
func resolve(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}
