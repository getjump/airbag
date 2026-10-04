//go:build linux

package sandbox

import (
	"fmt"
	"math"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The agent runs with no_new_privs and a seccomp filter that refuses
// two terminal ioctls: TIOCSTI pushes bytes into a terminal's input as
// if typed, TIOCLINUX can do the same on a Linux console. The agent's
// terminal is already a pseudo-terminal of its own (tty.go), so this is
// a second layer, as in bubblewrap and Flatpak.

// seccomp_data offsets: nr, arch, then the arguments. Only the low 32
// bits of the request are compared: the kernel truncates ioctl's
// request to an int, so a filter on the full 64 bits could be passed
// with high bits set (CVE-2019-10063 in Flatpak). Both supported
// architectures are little-endian, so the low half comes first.
const (
	offNr       = 0
	offArch     = 4
	offArg1Low  = 16 + 8*1
	x32Bit      = 0x40000000
	seccompDeny = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
)

type archIoctl struct {
	arch uint32
	nrs  []uint32 // ioctl's syscall numbers in this ABI
}

// ioctlABIs lists the ABIs a process of this architecture can call
// ioctl through, including the 32-bit compatibility ones.
func ioctlABIs(goarch string) []archIoctl {
	switch goarch {
	case "amd64":
		return []archIoctl{
			{unix.AUDIT_ARCH_X86_64, []uint32{16, x32Bit | 16, x32Bit | 514}},
			{unix.AUDIT_ARCH_I386, []uint32{54}},
		}
	case "arm64":
		return []archIoctl{
			{unix.AUDIT_ARCH_AARCH64, []uint32{29}},
			{unix.AUDIT_ARCH_ARM, []uint32{54}},
		}
	}
	return nil
}

// ttyFilter builds the BPF program. Per ABI: load the architecture,
// skip the block on mismatch, load the syscall number and jump to the
// request check on ioctl. Everything else is allowed.
func ttyFilter(abis []archIoctl) []unix.SockFilter {
	ld := func(off uint32) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: off}
	}
	jeq := func(k uint32, jt, jf uint8) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: jt, Jf: jf, K: k}
	}
	ret := func(k uint32) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: k}
	}
	var p []unix.SockFilter
	var toCheck []int
	for _, a := range abis {
		p = append(p, ld(offArch), jeq(a.arch, 0, jump(len(a.nrs)+2)), ld(offNr))
		for _, nr := range a.nrs {
			toCheck = append(toCheck, len(p))
			p = append(p, jeq(nr, 0, 0))
		}
		p = append(p, ret(unix.SECCOMP_RET_ALLOW))
	}
	p = append(p, ret(unix.SECCOMP_RET_ALLOW))
	check := len(p)
	for _, i := range toCheck {
		p[i].Jt = jump(check - i - 1)
	}
	p = append(p,
		ld(offArg1Low),
		jeq(unix.TIOCSTI, 2, 0),
		jeq(unix.TIOCLINUX, 1, 0),
		ret(unix.SECCOMP_RET_ALLOW),
		ret(seccompDeny),
	)
	return p
}

// jump is a BPF jump offset, which has 8 bits. The filter is a few
// dozen instructions: an offset that does not fit is a bug here, and
// wrapped it would jump somewhere else.
func jump(n int) uint8 {
	if n < 0 || n > math.MaxUint8 {
		panic(fmt.Sprintf("seccomp: a jump over %d instructions", n))
	}
	return uint8(n)
}

// restrictAgent sets no_new_privs and installs the filter on every
// thread of this process; the agent inherits both. TSYNC also copies
// no_new_privs to the other threads, so one prctl on this thread is
// enough.
func restrictAgent() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	p := ttyFilter(ioctlABIs(runtime.GOARCH))
	if len(p) == 1 {
		return nil // an architecture without a filter: only no_new_privs
	}
	if len(p) > unix.BPF_MAXINSNS {
		return fmt.Errorf("seccomp: a filter of %d instructions", len(p))
	}
	prog := unix.SockFprog{Len: uint16(len(p)), Filter: &p[0]} //nolint:gosec // at most BPF_MAXINSNS, checked above
	_, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&prog))) //nolint:gosec // seccomp(2) takes a pointer to the program; KeepAlive below
	runtime.KeepAlive(p)
	if e != 0 {
		return fmt.Errorf("seccomp: %w", e)
	}
	return nil
}
