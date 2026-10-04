package review

import "golang.org/x/sys/unix"

// renameExchange swaps two paths atomically (a variable for tests).
var renameExchange = func(a, b string) error {
	return unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE)
}

// renameNoReplace renames from to to, failing with EEXIST if to exists.
var renameNoReplace = func(from, to string) error {
	return unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_NOREPLACE)
}
