package review

import "golang.org/x/sys/unix"

// renameExchange swaps two paths atomically.
func renameExchange(a, b string) error { return unix.RenamexNp(a, b, unix.RENAME_SWAP) }

// renameNoReplace renames from to to, failing with EEXIST if to exists.
func renameNoReplace(from, to string) error { return unix.RenamexNp(from, to, unix.RENAME_EXCL) }
