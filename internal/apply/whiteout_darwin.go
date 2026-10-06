package apply

import (
	"errors"
	"os"
)

// whiteoutAt is for an overlayfs upper layer, which macOS has none of:
// its sessions are clones, where a deletion is the file's absence.
func whiteoutAt(*os.File, string) error {
	return errors.New("no overlayfs upper layer on macOS")
}
