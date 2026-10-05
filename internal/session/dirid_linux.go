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

// fsIocGetversion is FS_IOC_GETVERSION, _IOR('v', 1, long) on 64-bit
// Linux.
const fsIocGetversion = 0x80087601

// gen is p's inode generation (FS_IOC_GETVERSION), or 0 where the
// filesystem gives none. ext2, ext3, ext4, xfs and btrfs keep it on
// disk and give a new inode in a removed one's place another one.
func gen(p string) uint64 {
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0
	}
	defer func() { _ = unix.Close(fd) }()
	// The request says 8 bytes, and a FUSE server's answer is copied
	// back at that size; ext4, xfs and btrfs write an int.
	v, err := unix.IoctlGetInt(fd, fsIocGetversion)
	if err != nil {
		return 0
	}
	return uint64(uint32(v)) //nolint:gosec // the generation's 32 bits
}

// settle copies a directory on an overlay up to the top layer before
// its identity is recorded, by setting its times to what they are. An
// overlay reports the creation time of whichever layer holds the
// directory now, and the first write below one still in a lower layer
// (apply's own) would copy it up, giving it a new one while its inode
// number stays. Once up, it keeps its creation time, and a directory
// made again in its place, or a new container's copy from the same
// image, has another. It reports false on an overlay where that could
// not be done.
func settle(p string) bool {
	var fs unix.Statfs_t
	if unix.Statfs(p, &fs) != nil || fs.Type != unix.OVERLAYFS_SUPER_MAGIC {
		return true
	}
	var st unix.Stat_t
	if unix.Lstat(p, &st) != nil {
		return false
	}
	return unix.UtimesNanoAt(unix.AT_FDCWD, p, []unix.Timespec{st.Atim, st.Mtim}, unix.AT_SYMLINK_NOFOLLOW) == nil
}
