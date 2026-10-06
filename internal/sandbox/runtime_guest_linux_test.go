//go:build linux

package sandbox

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestGuestFilterRefusesOnlyClone3(t *testing.T) {
	p := guestFilter()
	for _, nr := range []uint32{unix.SYS_CLONE3, unix.SYS_CLONE3 | x32SyscallBit} {
		if got := runBPF(t, p, seccompData(unix.AUDIT_ARCH_X86_64, nr, 0, 0)); got != retENOSYS {
			t.Fatalf("clone3 %#x: verdict %#x, want ENOSYS so glibc falls back to clone", nr, got)
		}
	}
	for _, nr := range []uint32{unix.SYS_CLONE, unix.SYS_READ, unix.SYS_EXECVE, unix.SYS_UNSHARE} {
		if got := runBPF(t, p, seccompData(unix.AUDIT_ARCH_X86_64, nr, 0, 0)); got != retAllow {
			t.Fatalf("nr %d: verdict %#x, want allow (left to the other filters)", nr, got)
		}
	}
}
