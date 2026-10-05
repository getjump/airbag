package links

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Inside reports whether p is root or below it, compared as files, not
// as names: on macOS case and firmlinks give one directory several
// names, and a bind mount does anywhere. p need not exist; its longest
// existing part is compared.
func Inside(p string, root os.FileInfo) bool {
	for d := p; ; d = filepath.Dir(d) {
		if fi, err := os.Stat(d); err == nil && os.SameFile(fi, root) {
			return true
		}
		if filepath.Dir(d) == d {
			return false
		}
	}
}

// Installed reports whether p is an installed program, which is what a
// venv's interpreter links to: a regular file with an execute bit, owned
// by root, in directories owned by root that anyone may search, none of
// them writable by the user. Other files anyone may read are not public:
// a machine's configuration can carry credentials, and a file root wrote
// into a user's folder can be the user's data. A directory never is: what
// lies below it is not known, and on macOS firmlinks join user data into
// /usr and /System. Something that does not exist is not public either:
// what appears there later, a process's files under /proc among them, is
// not known now.
func Installed(p string) bool {
	file, ok := placeOf(p)
	if !ok {
		return false
	}
	var dirs []place
	for d := filepath.Dir(p); ; d = filepath.Dir(d) {
		dir, ok := placeOf(d)
		if !ok {
			return false
		}
		dirs = append(dirs, dir)
		if filepath.Dir(d) == d {
			break
		}
	}
	return program(file, dirs)
}

// place is what Installed looks at in a file or directory: its mode, owner,
// and whether the user may write it.
type place struct {
	mode     fs.FileMode
	uid      int64
	writable bool
}

func placeOf(p string) (place, bool) {
	fi, err := os.Stat(p)
	if err != nil {
		return place{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return place{}, false
	}
	return place{mode: fi.Mode(), uid: int64(st.Uid), writable: unix.Access(p, unix.W_OK) == nil}, true
}

// program reports whether file, below dirs, is an installed program: see
// Installed.
func program(file place, dirs []place) bool {
	if !file.mode.IsRegular() || file.mode&0o111 == 0 || file.uid != 0 || file.writable {
		return false
	}
	for _, d := range dirs {
		if !d.mode.IsDir() || d.mode&0o001 == 0 || d.uid != 0 || d.writable {
			return false
		}
	}
	return true
}
