//go:build linux && 386

package main

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// socketcallSocket creates an AF_INET socket through i386's socketcall
// multiplexer (SYS_SOCKET sub-call 1). The seccomp filter does not
// family-check socketcall, so in --strict mode it refuses the whole
// sub-call; by default the socket is created.
//
//nolint:gosec // unsafe: socketcall takes a pointer to its argument array
func socketcallSocket() string {
	args := [3]uint32{uint32(unix.AF_INET), uint32(unix.SOCK_DGRAM), 0}
	fd, _, e := unix.Syscall(unix.SYS_SOCKETCALL, 1 /* SYS_SOCKET */, uintptr(unsafe.Pointer(&args)), 0)
	if e == 0 {
		_ = unix.Close(int(fd))
	}
	return result(e)
}
