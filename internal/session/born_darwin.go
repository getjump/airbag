package session

import "syscall"

// born is the directory's creation time in nanoseconds, which APFS and
// HFS+ record.
func born(_ string, st *syscall.Stat_t) int64 {
	return st.Birthtimespec.Sec*1e9 + st.Birthtimespec.Nsec
}
