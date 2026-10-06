package apply

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// whiteoutAt is for an overlayfs upper layer, which macOS has none of:
// its sessions are clones, where a deletion is the file's absence.
func whiteoutAt(*os.File, string) error {
	return errors.New("no overlayfs upper layer on macOS")
}

// renameNoReplace renames from to to, both in dir, and fails with EEXIST
// rather than replace a to that is there.
func renameNoReplace(dir *os.File, from, to string) error {
	fd := int(dir.Fd())
	return unix.RenameatxNp(fd, from, fd, to, unix.RENAME_EXCL)
}
