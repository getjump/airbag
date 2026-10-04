package sandbox

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// runBPF interprets the subset of classic BPF the filter uses.
func runBPF(t *testing.T, p []unix.SockFilter, data []byte) uint32 {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(p); pc++ {
		in := p[pc]
		switch in.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			a = binary.LittleEndian.Uint32(data[in.K:])
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if a == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return in.K
		default:
			t.Fatalf("unexpected opcode %#x at %d", in.Code, pc)
		}
	}
	t.Fatal("program fell off the end")
	return 0
}

func seccompData(arch, nr uint32, arg1 uint64) []byte {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b[offNr:], nr)
	binary.LittleEndian.PutUint32(b[offArch:], arch)
	binary.LittleEndian.PutUint64(b[16+8:], arg1)
	return b
}

func TestTTYFilter(t *testing.T) {
	for _, goarch := range []string{"amd64", "arm64"} {
		abis := ioctlABIs(goarch)
		p := ttyFilter(abis)
		for _, a := range abis {
			for _, nr := range a.nrs {
				for _, c := range []struct {
					arg  uint64
					want uint32
				}{
					{unix.TIOCSTI, seccompDeny},
					{unix.TIOCLINUX, seccompDeny},
					{1<<32 | unix.TIOCSTI, seccompDeny}, // high bits are ignored by the kernel
					{unix.TIOCGWINSZ, unix.SECCOMP_RET_ALLOW},
					{unix.TCGETS, unix.SECCOMP_RET_ALLOW},
				} {
					if got := runBPF(t, p, seccompData(a.arch, nr, c.arg)); got != c.want {
						t.Errorf("%s arch %#x nr %d arg %#x: got %#x, want %#x", goarch, a.arch, nr, c.arg, got, c.want)
					}
				}
			}
			// Another syscall with the same argument passes.
			if got := runBPF(t, p, seccompData(a.arch, 1, unix.TIOCSTI)); got != unix.SECCOMP_RET_ALLOW {
				t.Errorf("%s arch %#x: write with TIOCSTI-like arg denied", goarch, a.arch)
			}
		}
		// An unknown architecture passes (the filter is a second layer).
		if got := runBPF(t, p, seccompData(0x1234, 16, unix.TIOCSTI)); got != unix.SECCOMP_RET_ALLOW {
			t.Errorf("%s: unknown arch denied", goarch)
		}
	}
}
