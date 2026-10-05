package session

import "syscall"

// born is the directory's creation time in nanoseconds, which APFS and
// HFS+ record.
func born(_ string, st *syscall.Stat_t) int64 {
	return st.Birthtimespec.Sec*1e9 + st.Birthtimespec.Nsec
}

// fsID is 0 on macOS: its f_fsid is the device number, which says
// nothing more.
func fsID(string) uint64 { return 0 }

// gen is 0 on macOS: st_gen reads as 0 unless the caller is root.
func gen(string) uint64 { return 0 }
