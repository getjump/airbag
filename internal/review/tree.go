package review

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// ScanTree compares a branch kept as a full copy (an APFS clone on
// macOS) with the real tree it was made from. Entries that differ are
// Added or Modified, with Upper in the branch; entries gone from the
// branch are Deleted (a deleted directory is one change, not one per
// file inside). Unlike overlayfs there are no whiteouts to read: a
// deletion is what the real tree has and the branch lacks.
//
// The real tree must not change during the session; a change made there
// shows up as the opposite change in the branch.
func ScanTree(layer, real, branch string) ([]Change, error) {
	var out []Change
	err := filepath.WalkDir(branch, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == branch {
			return nil
		}
		rel, _ := filepath.Rel(branch, p)
		c := Change{Layer: layer, Rel: rel, Path: filepath.Join(real, rel), Upper: p}
		info, err := d.Info()
		if err != nil {
			return err
		}
		c.Mode = info.Mode().Perm()
		lst, lerr := os.Lstat(c.Path)
		switch {
		case info.IsDir():
			c.Type = fs.ModeDir
			if lerr == nil && lst.IsDir() {
				return nil
			}
			if lerr == nil {
				c.Kind = Replaced
			} else {
				c.Kind = Added
			}
		case info.Mode()&fs.ModeSymlink != 0:
			c.Type = fs.ModeSymlink
			c.Kind = Added
			if lerr == nil {
				old, _ := os.Readlink(c.Path)
				cur, _ := os.Readlink(p)
				if lst.Mode()&fs.ModeSymlink != 0 && old == cur {
					return nil
				}
				c.Kind = Modified
			}
		default:
			c.Kind = Added
			if lerr == nil {
				if info.Mode().IsRegular() && lst.Mode().IsRegular() && lst.Mode().Perm() == c.Mode && sameContent(c.Path, p) {
					return nil
				}
				c.Kind = Modified
			}
		}
		out = append(out, c)
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	// A walk does not enter a root that is a link (a workspace named
	// through one), and would miss every deletion: it starts where the
	// link leads, and names the real files by the workspace's path.
	root := real
	if r, err := filepath.EvalSymlinks(real); err == nil {
		root = r
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if _, err := os.Lstat(filepath.Join(branch, rel)); err == nil {
			return nil
		}
		c := Change{Layer: layer, Rel: rel, Path: filepath.Join(real, rel), Upper: filepath.Join(branch, rel), Kind: Deleted, Type: d.Type().Type()}
		out = append(out, c)
		if d.IsDir() {
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out, nil
}
