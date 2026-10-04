//go:build linux

package sandbox

import (
	"bufio"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
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
		case unix.BPF_JMP | unix.BPF_JA:
			pc += int(int32(in.K))
		case unix.BPF_RET | unix.BPF_K:
			return in.K
		default:
			t.Fatalf("unexpected opcode %#x at %d", in.Code, pc)
		}
	}
	t.Fatal("program fell off the end")
	return 0
}

func seccompData(arch, nr uint32, arg0, arg1 uint64) []byte {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b[offNr:], nr)
	binary.LittleEndian.PutUint32(b[offArch:], arch)
	binary.LittleEndian.PutUint64(b[16+8*0:], arg0)
	binary.LittleEndian.PutUint64(b[16+8*1:], arg1)
	return b
}

// verdict runs the built filter for one (arch, nr, args) triple.
func verdict(t *testing.T, strict bool, arch, nr uint32, arg0, arg1 uint64) uint32 {
	p := agentFilter(abisFor(runtime_GOARCH(t)), strict)
	return runBPF(t, p, seccompData(arch, nr, arg0, arg1))
}

// runtime_GOARCH returns the arch the filter is built for. The number
// tables are the native one's; the test drives whichever host it is on.
func runtime_GOARCH(t *testing.T) string {
	switch a := goArch(); a {
	case "amd64", "arm64":
		return a
	default:
		t.Skipf("no syscall table for %s", a)
		return ""
	}
}

// TestDeniedCalls checks every denied number, on every ABI of the build
// arch, with and without the x32 bit where it applies.
func TestDeniedCalls(t *testing.T) {
	abis := abisFor(runtime_GOARCH(t))
	for _, strict := range []bool{false, true} {
		p := agentFilter(abis, strict)
		if len(p) > 4096 {
			t.Fatalf("program too long: %d", len(p))
		}
		for _, a := range abis {
			variants := []uint32{0}
			if a.x32 {
				variants = append(variants, x32SyscallBit)
			}
			check := func(name string, nr uint32, want uint32) {
				if nr == 0 {
					return
				}
				for _, v := range variants {
					got := runBPF(t, p, seccompData(a.audit, nr|v, 0, 0))
					if got != want {
						t.Errorf("strict=%v arch=%#x %s(nr=%d|%#x): got %#x want %#x",
							strict, a.audit, name, nr, v, got, want)
					}
				}
			}
			for _, nr := range a.nrs.eperm() {
				check("eperm", nr, retEPERM)
			}
			for _, nr := range a.nrs.enosys() {
				check("io_uring", nr, retENOSYS)
			}
			for _, nr := range a.nrs.strictENOSYS() {
				want := uint32(retAllow)
				if strict {
					want = retENOSYS
				}
				check("mount-api", nr, want)
			}
		}
	}
}

// TestIoctlFilter keeps the terminal-injection refusals, including the
// high-bit and x32 cases.
func TestIoctlFilter(t *testing.T) {
	abis := abisFor(runtime_GOARCH(t))
	p := agentFilter(abis, false)
	for _, a := range abis {
		nrs := []uint32{a.nrs.ioctl}
		if a.x32 {
			nrs = append(nrs, a.nrs.ioctl|x32SyscallBit, 514|x32SyscallBit)
		}
		for _, nr := range nrs {
			for _, c := range []struct {
				arg1 uint64
				want uint32
			}{
				{unix.TIOCSTI, retEPERM},
				{unix.TIOCLINUX, retEPERM},
				{1<<32 | unix.TIOCSTI, retEPERM}, // high bits ignored by the kernel
				{unix.TIOCGWINSZ, retAllow},
				{unix.TCGETS, retAllow},
			} {
				if got := runBPF(t, p, seccompData(a.audit, nr, 0, c.arg1)); got != c.want {
					t.Errorf("arch %#x ioctl nr %d arg %#x: got %#x want %#x", a.audit, nr, c.arg1, got, c.want)
				}
			}
		}
		// A non-ioctl syscall with a TIOCSTI-shaped argument is allowed.
		if got := runBPF(t, p, seccompData(a.audit, a.nrs.socket, unix.AF_INET, unix.TIOCSTI)); got == retEPERM {
			t.Errorf("arch %#x: a non-ioctl call refused on its argument", a.audit)
		}
	}
}

// TestSocketFilter: allowed families pass, the rest are refused, on
// every ABI.
func TestSocketFilter(t *testing.T) {
	abis := abisFor(runtime_GOARCH(t))
	p := agentFilter(abis, false)
	denied := []uint32{unix.AF_VSOCK, unix.AF_PACKET, unix.AF_BLUETOOTH, unix.AF_IPX}
	for _, a := range abis {
		nrs := []uint32{a.nrs.socket}
		if a.x32 {
			nrs = append(nrs, a.nrs.socket|x32SyscallBit)
		}
		for _, nr := range nrs {
			for _, fam := range allowedSocketFamilies {
				if got := runBPF(t, p, seccompData(a.audit, nr, uint64(fam), 0)); got != retAllow {
					t.Errorf("arch %#x socket family %d: got %#x want allow", a.audit, fam, got)
				}
			}
			for _, fam := range denied {
				if got := runBPF(t, p, seccompData(a.audit, nr, uint64(fam), 0)); got != retEPERM {
					t.Errorf("arch %#x socket family %d: got %#x want EPERM", a.audit, fam, got)
				}
				// A high-bit-set family must not sneak past (int arg).
				if got := runBPF(t, p, seccompData(a.audit, nr, 1<<32|uint64(fam), 0)); got != retEPERM {
					t.Errorf("arch %#x socket family %d high bits: got %#x want EPERM", a.audit, fam, got)
				}
			}
		}
	}
}

// TestPersonalityFilter: the safe values pass (0xffffffff is the query),
// a domain switch is refused.
func TestPersonalityFilter(t *testing.T) {
	abis := abisFor(runtime_GOARCH(t))
	p := agentFilter(abis, false)
	for _, a := range abis {
		for _, v := range allowedPersonality {
			if got := runBPF(t, p, seccompData(a.audit, a.nrs.personality, uint64(v), 0)); got != retAllow {
				t.Errorf("arch %#x personality %#x: got %#x want allow", a.audit, v, got)
			}
		}
		if got := runBPF(t, p, seccompData(a.audit, a.nrs.personality, 0x4, 0)); got != retEPERM {
			t.Errorf("arch %#x personality switch: got %#x want EPERM", a.audit, got)
		}
	}
}

// TestAllowedCalls: a set of calls the agent and its tools rely on must
// pass on the native ABI. Numbers are the build arch's own, from x/sys.
func TestAllowedCalls(t *testing.T) {
	runtime_GOARCH(t)
	abis := abisFor(goArch())
	p := agentFilter(abis, true) // strict is the stricter case
	native := abis[0].audit
	allowed := map[string]uint32{
		"read": unix.SYS_READ, "write": unix.SYS_WRITE, "openat": unix.SYS_OPENAT,
		"close": unix.SYS_CLOSE, "mmap": unix.SYS_MMAP, "futex": unix.SYS_FUTEX,
		"clone": unix.SYS_CLONE, "execve": unix.SYS_EXECVE,
		"ptrace": unix.SYS_PTRACE, "process_vm_readv": unix.SYS_PROCESS_VM_READV,
		"mount": unix.SYS_MOUNT, "umount2": unix.SYS_UMOUNT2,
		"pivot_root": unix.SYS_PIVOT_ROOT, "setns": unix.SYS_SETNS,
		"unshare": unix.SYS_UNSHARE, "chroot": unix.SYS_CHROOT,
	}
	for name, nr := range allowed {
		if got := runBPF(t, p, seccompData(native, nr, 0, 0)); got != retAllow {
			t.Errorf("%s (nr %d) refused, want allow (got %#x)", name, nr, got)
		}
	}
}

// TestUnknownArch: a foreign architecture is killed, not allowed.
func TestUnknownArch(t *testing.T) {
	abis := abisFor(runtime_GOARCH(t))
	p := agentFilter(abis, false)
	if got := runBPF(t, p, seccompData(0x1234, 16, 0, unix.TIOCSTI)); got != retKill {
		t.Errorf("unknown arch: got %#x want kill", got)
	}
}

// TestSyscallNumbers cross-checks the hand-maintained number tables
// against golang.org/x/sys's generated zsysnum tables, so a wrong or
// stale number is caught in CI rather than shipped.
func TestSyscallNumbers(t *testing.T) {
	dir := xsysUnixDir(t)
	cases := []struct {
		file string
		nrs  nrSet
	}{
		{"zsysnum_linux_amd64.go", nrsAMD64},
		{"zsysnum_linux_386.go", nrs386},
		{"zsysnum_linux_arm64.go", nrsARM64},
		{"zsysnum_linux_arm.go", nrsARM},
	}
	for _, c := range cases {
		want := parseSysnums(t, filepath.Join(dir, c.file))
		check := func(sym string, got uint32) {
			if got == 0 {
				return // marked absent on this ABI
			}
			if w, ok := want[sym]; !ok {
				t.Errorf("%s: %s not in x/sys table", c.file, sym)
			} else if w != got {
				t.Errorf("%s: %s table has %d, x/sys has %d", c.file, sym, got, w)
			}
		}
		n := c.nrs
		check("SYS_IO_URING_SETUP", n.ioURingSetup)
		check("SYS_IO_URING_ENTER", n.ioURingEnter)
		check("SYS_IO_URING_REGISTER", n.ioURingRegister)
		check("SYS_BPF", n.bpf)
		check("SYS_PERF_EVENT_OPEN", n.perfEventOpen)
		check("SYS_USERFAULTFD", n.userfaultfd)
		check("SYS_KEYCTL", n.keyctl)
		check("SYS_ADD_KEY", n.addKey)
		check("SYS_REQUEST_KEY", n.requestKey)
		check("SYS_KEXEC_LOAD", n.kexecLoad)
		check("SYS_KEXEC_FILE_LOAD", n.kexecFileLoad)
		check("SYS_INIT_MODULE", n.initModule)
		check("SYS_FINIT_MODULE", n.finitModule)
		check("SYS_DELETE_MODULE", n.deleteModule)
		check("SYS_OPEN_BY_HANDLE_AT", n.openByHandleAt)
		check("SYS_QUOTACTL", n.quotactl)
		check("SYS_ACCT", n.acct)
		check("SYS_SWAPON", n.swapon)
		check("SYS_SWAPOFF", n.swapoff)
		check("SYS_REBOOT", n.reboot)
		check("SYS_SYSLOG", n.syslog)
		check("SYS_USELIB", n.uselib)
		check("SYS_LOOKUP_DCOOKIE", n.lookupDcookie)
		check("SYS_OPEN_TREE", n.openTree)
		check("SYS_MOVE_MOUNT", n.moveMount)
		check("SYS_FSOPEN", n.fsopen)
		check("SYS_FSCONFIG", n.fsconfig)
		check("SYS_FSMOUNT", n.fsmount)
		check("SYS_FSPICK", n.fspick)
		check("SYS_MOUNT_SETATTR", n.mountSetattr)
		check("SYS_IOCTL", n.ioctl)
		check("SYS_SOCKET", n.socket)
		check("SYS_PERSONALITY", n.personality)
	}
}

func goArch() string { return runtime.GOARCH }

func xsysUnixDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "golang.org/x/sys").Output()
	if err != nil {
		t.Skipf("locate golang.org/x/sys: %v", err)
	}
	dir := filepath.Join(strings.TrimSpace(string(out)), "unix")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("x/sys unix dir: %v", err)
	}
	return dir
}

var sysnumLine = regexp.MustCompile(`^\s*(SYS_[A-Z0-9_]+)\s*=\s*(\d+)`)

func parseSysnums(t *testing.T, path string) map[string]uint32 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("open %s: %v", path, err)
	}
	defer f.Close()
	out := map[string]uint32{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := sysnumLine.FindStringSubmatch(sc.Text()); m != nil {
			n, _ := strconv.Atoi(m[2])
			out[m[1]] = uint32(n)
		}
	}
	return out
}
