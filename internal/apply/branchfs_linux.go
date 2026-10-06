package apply

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// whiteoutAt makes name in dir overlayfs's whiteout: a 0:0 character
// device (unprivileged since Linux 5.8).
func whiteoutAt(dir *os.File, name string) error {
	return unix.Mknodat(int(dir.Fd()), name, syscall.S_IFCHR, 0)
}

// renameNoReplace renames from to to, both in dir, and fails with EEXIST
// rather than replace a to that is there.
func renameNoReplace(dir *os.File, from, to string) error {
	fd := int(dir.Fd())
	return unix.Renameat2(fd, from, fd, to, unix.RENAME_NOREPLACE)
}
