package review

import "golang.org/x/sys/unix"

// renameExchange swaps two paths atomically (a variable for tests).
var renameExchange = func(a, b string) error { return unix.RenamexNp(a, b, unix.RENAME_SWAP) }

// renameNoReplace renames from to to, failing with EEXIST if to exists.
var renameNoReplace = func(from, to string) error { return unix.RenamexNp(from, to, unix.RENAME_EXCL) }
