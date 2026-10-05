package session

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// born is p's creation time in nanoseconds from statx, or 0 where the
// filesystem does not record it.
func born(p string, _ *syscall.Stat_t) int64 {
	var stx unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, p, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &stx) != nil || stx.Mask&unix.STATX_BTIME == 0 {
		return 0
	}
	return stx.Btime.Sec*1e9 + int64(stx.Btime.Nsec)
}
