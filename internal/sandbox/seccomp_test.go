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
			pc += int(in.K) // forward only: resolve rejects anything else
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

// numbered is one ABI's numbering as the filter sees it: x32's numbers
// carry the x32 bit under the x86_64 arch value.
type numbered struct {
	audit uint32
	n     nrSet
	bit   uint32
}

// allNumberings lists every ABI numbering of both build arches, so each
// test covers x86_64, x32, i386, aarch64 and arm whatever the host is.
func allNumberings() []struct {
	goarch string
	ns     []numbered
} {
	var out []struct {
		goarch string
		ns     []numbered
	}
	for _, goarch := range []string{"amd64", "arm64"} {
		var ns []numbered
		for _, a := range abisFor(goarch) {
			ns = append(ns, numbered{a.audit, a.nrs, 0})
			if a.x32 != nil {
				ns = append(ns, numbered{a.audit, *a.x32, x32SyscallBit})
			}
		}
		out = append(out, struct {
			goarch string
			ns     []numbered
		}{goarch, ns})
	}
	return out
}

// TestDeniedCalls checks every denied number on every ABI.
func TestDeniedCalls(t *testing.T) {
	for _, g := range allNumberings() {
		for _, strict := range []bool{false, true} {
			p := agentFilter(abisFor(g.goarch), strict)
			if len(p) > 4096 {
				t.Fatalf("program too long: %d", len(p))
			}
			for _, a := range g.ns {
				check := func(name string, nr uint32, want uint32) {
					if got := runBPF(t, p, seccompData(a.audit, nr|a.bit, 0, 0)); got != want {
						t.Errorf("%s strict=%v arch=%#x %s(nr=%d|%#x): got %#x want %#x",
							g.goarch, strict, a.audit, name, nr, a.bit, got, want)
					}
				}
				for _, nr := range a.n.eperm() {
					check("eperm", nr, retEPERM)
				}
				for _, nr := range a.n.enosys() {
					check("io_uring", nr, retENOSYS)
				}
				for _, nr := range a.n.strictENOSYS() {
					want := uint32(retAllow)
					if strict {
						want = retENOSYS
					}
					check("mount-api", nr, want)
				}
			}
		}
	}
}

// TestX32OwnNumbers: x32's own numbers for kexec_load and ioctl are
// covered, not only the x86_64 numbers with the x32 bit.
func TestX32OwnNumbers(t *testing.T) {
	p := agentFilter(abisFor("amd64"), false)
	if got := runBPF(t, p, seccompData(unix.AUDIT_ARCH_X86_64, 528|x32SyscallBit, 0, 0)); got != retEPERM {
		t.Errorf("x32 kexec_load (528): got %#x want EPERM", got)
	}
	if got := runBPF(t, p, seccompData(unix.AUDIT_ARCH_X86_64, 514|x32SyscallBit, 0, unix.TIOCSTI)); got != retEPERM {
		t.Errorf("x32 ioctl (514) TIOCSTI: got %#x want EPERM", got)
	}
}

// TestIoctlFilter keeps the terminal-injection refusals, including the
// high-bit case, on every ABI.
func TestIoctlFilter(t *testing.T) {
	for _, g := range allNumberings() {
		p := agentFilter(abisFor(g.goarch), false)
		for _, a := range g.ns {
			nr := a.n.ioctl | a.bit
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
					t.Errorf("%s arch %#x ioctl nr %#x arg %#x: got %#x want %#x", g.goarch, a.audit, nr, c.arg1, got, c.want)
				}
			}
			// A non-ioctl syscall with a TIOCSTI-shaped argument is allowed.
			if got := runBPF(t, p, seccompData(a.audit, a.n.socket|a.bit, unix.AF_INET, unix.TIOCSTI)); got == retEPERM {
				t.Errorf("%s arch %#x: a non-ioctl call refused on its argument", g.goarch, a.audit)
			}
		}
	}
}

// TestSocketFilter: allowed families pass, the rest are refused, for
// socket and socketpair on every ABI.
func TestSocketFilter(t *testing.T) {
	denied := []uint32{unix.AF_VSOCK, unix.AF_PACKET, unix.AF_TIPC, unix.AF_BLUETOOTH, unix.AF_IPX}
	for _, g := range allNumberings() {
		p := agentFilter(abisFor(g.goarch), false)
		for _, a := range g.ns {
			for name, nr := range map[string]uint32{"socket": a.n.socket, "socketpair": a.n.socketpair} {
				if nr == 0 {
					t.Errorf("%s arch %#x: no %s number", g.goarch, a.audit, name)
					continue
				}
				nr |= a.bit
				for _, fam := range allowedSocketFamilies {
					if got := runBPF(t, p, seccompData(a.audit, nr, uint64(fam), 0)); got != retAllow {
						t.Errorf("%s arch %#x %s family %d: got %#x want allow", g.goarch, a.audit, name, fam, got)
					}
				}
				for _, fam := range denied {
					if got := runBPF(t, p, seccompData(a.audit, nr, uint64(fam), 0)); got != retEPERM {
						t.Errorf("%s arch %#x %s family %d: got %#x want EPERM", g.goarch, a.audit, name, fam, got)
					}
					// The family is an int: high bits must not change the verdict.
					if got := runBPF(t, p, seccompData(a.audit, nr, 1<<32|uint64(fam), 0)); got != retEPERM {
						t.Errorf("%s arch %#x %s family %d high bits: got %#x want EPERM", g.goarch, a.audit, name, fam, got)
					}
				}
			}
		}
	}
}

// TestPersonalityFilter: the safe values pass (0xffffffff is the query),
// a domain switch is refused, on every ABI.
func TestPersonalityFilter(t *testing.T) {
	for _, g := range allNumberings() {
		p := agentFilter(abisFor(g.goarch), false)
		for _, a := range g.ns {
			nr := a.n.personality | a.bit
			for _, v := range allowedPersonality {
				if got := runBPF(t, p, seccompData(a.audit, nr, uint64(v), 0)); got != retAllow {
					t.Errorf("%s arch %#x personality %#x: got %#x want allow", g.goarch, a.audit, v, got)
				}
			}
			if got := runBPF(t, p, seccompData(a.audit, nr, 0x4, 0)); got != retEPERM {
				t.Errorf("%s arch %#x personality switch: got %#x want EPERM", g.goarch, a.audit, got)
			}
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
		check("SYS_SOCKETPAIR", n.socketpair)
		check("SYS_PERSONALITY", n.personality)
	}
}

func goArch() string { return runtime.GOARCH }

func xsysUnixDir(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "go", "list", "-m", "-f", "{{.Dir}}", "golang.org/x/sys").Output()
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
	defer func() { _ = f.Close() }()
	out := map[string]uint32{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := sysnumLine.FindStringSubmatch(sc.Text()); m != nil {
			n, err := strconv.ParseUint(m[2], 10, 32)
			if err != nil {
				t.Fatalf("%s: %q: %v", path, sc.Text(), err)
			}
			out[m[1]] = uint32(n)
		}
	}
	return out
}

// nrsByName maps kernel syscall names to an nrSet's numbers.
func nrsByName(n nrSet) map[string]uint32 {
	return map[string]uint32{
		"io_uring_setup": n.ioURingSetup, "io_uring_enter": n.ioURingEnter, "io_uring_register": n.ioURingRegister,
		"bpf": n.bpf, "perf_event_open": n.perfEventOpen, "userfaultfd": n.userfaultfd,
		"keyctl": n.keyctl, "add_key": n.addKey, "request_key": n.requestKey,
		"kexec_load": n.kexecLoad, "kexec_file_load": n.kexecFileLoad,
		"init_module": n.initModule, "finit_module": n.finitModule, "delete_module": n.deleteModule,
		"open_by_handle_at": n.openByHandleAt, "quotactl": n.quotactl, "acct": n.acct,
		"swapon": n.swapon, "swapoff": n.swapoff, "reboot": n.reboot, "syslog": n.syslog, "uselib": n.uselib,
		"lookup_dcookie": n.lookupDcookie,
		"open_tree":      n.openTree, "move_mount": n.moveMount, "fsopen": n.fsopen,
		"fsconfig": n.fsconfig, "fsmount": n.fsmount, "fspick": n.fspick, "mount_setattr": n.mountSetattr,
		"ioctl": n.ioctl, "socket": n.socket, "socketpair": n.socketpair, "personality": n.personality,
	}
}

// TestX32SyscallNumbers pins nrsX32 to the kernel's syscall_64.tbl
// (testdata/syscall_64.tbl.excerpt, cited there). x/sys has no x32
// table. For each call the x32 number is its "x32" row if there is one,
// else its "common" row; a call with only a "64" row has no x32 entry
// and must be 0 in nrsX32.
func TestX32SyscallNumbers(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "syscall_64.tbl.excerpt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	type row struct {
		nr  uint32
		abi string
	}
	rows := map[string][]row{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		nr, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			t.Fatalf("bad row %q", sc.Text())
		}
		rows[fields[2]] = append(rows[fields[2]], row{uint32(nr), fields[1]})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	for name, got := range nrsByName(nrsX32) {
		rs, ok := rows[name]
		if !ok {
			t.Errorf("%s: not in the syscall_64.tbl excerpt", name)
			continue
		}
		var want uint32
		for _, r := range rs {
			switch r.abi {
			case "x32":
				want = r.nr
			case "common":
				if want == 0 {
					want = r.nr
				}
			}
		}
		if got != want {
			t.Errorf("x32 %s: table has %d, syscall_64.tbl gives %d (rows %v)", name, got, want, rs)
		}
	}
	// The x86_64 table must agree with the same rows ("common" or "64").
	for name, got := range nrsByName(nrsAMD64) {
		var want uint32
		for _, r := range rows[name] {
			if r.abi == "common" || r.abi == "64" {
				want = r.nr
			}
		}
		if got != want {
			t.Errorf("x86_64 %s: table has %d, syscall_64.tbl gives %d", name, got, want)
		}
	}
}

// A jump too long for BPF's 8-bit offset stops the build of the filter
// instead of wrapping around to another instruction.
func TestJumpFits(t *testing.T) {
	if jump(255) != 255 {
		t.Fatal("jump(255)")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("jump(256) wrapped")
		}
	}()
	jump(256)
}
