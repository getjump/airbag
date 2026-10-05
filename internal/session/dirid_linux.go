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

// fsID is the filesystem's ID from statfs (f_fsid), or 0 where it gives
// none. It stays when the filesystem is mounted again (ext4 and btrfs
// derive it from the filesystem's UUID) and, on btrfs, tells subvolumes
// and snapshots apart.
func fsID(p string) uint64 {
	var st unix.Statfs_t
	if unix.Statfs(p, &st) != nil {
		return 0
	}
	return uint64(uint32(st.Fsid.Val[0]))<<32 | uint64(uint32(st.Fsid.Val[1])) //nolint:gosec // the ID's bits, not a number
}
