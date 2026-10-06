package links

import (
	"io/fs"
	"testing"
)

// Each condition of an installed program, one at a time.
func TestProgram(t *testing.T) {
	bin := place{mode: 0o755}
	dir := place{mode: fs.ModeDir | 0o755}
	dirs := []place{dir, dir}
	if !program(bin, dirs) {
		t.Fatal("an installed program is not public")
	}
	for name, c := range map[string]struct {
		file place
		dirs []place
	}{
		"not a regular file":        {place{mode: fs.ModeDir | 0o755}, dirs},
		"no execute bit":            {place{mode: 0o644}, dirs},
		"not root's":                {place{mode: 0o755, uid: 1000}, dirs},
		"writable by the user":      {place{mode: 0o755, writable: true}, dirs},
		"in a directory not root's": {bin, []place{{mode: fs.ModeDir | 0o755, uid: 1000}, dir}},
		"in a writable directory":   {bin, []place{dir, {mode: fs.ModeDir | 0o755, writable: true}}},
		"in a closed directory":     {bin, []place{{mode: fs.ModeDir | 0o750}, dir}},
		"below a non-directory":     {bin, []place{{mode: 0o755}}},
	} {
		if program(c.file, c.dirs) {
			t.Errorf("%s: public", name)
		}
	}
}
