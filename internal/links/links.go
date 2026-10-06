// Package links resolves link targets the way the kernel does, for
// checks that must see where a link will lead.
package links

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Follow resolves name from the real directory dir one component at a
// time, as the kernel does: a link is replaced by where it leads before
// a later ".." applies. The part that does not exist yet is joined on as
// written. ok is false for a link on the way that leads nowhere or a
// loop of links.
func Follow(dir, name string) (string, bool) {
	cur := dir
	parts := strings.Split(name, "/")
	for i, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, part)
		fi, err := os.Lstat(next)
		if err != nil {
			return filepath.Join(append([]string{next}, parts[i+1:]...)...), true
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			if next, err = filepath.EvalSymlinks(next); err != nil {
				return "", false
			}
		}
		cur = next
	}
	return cur, true
}
