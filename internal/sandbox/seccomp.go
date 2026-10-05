//go:build linux

package sandbox

import (
	"fmt"
	"math"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The agent runs with no_new_privs and a seccomp filter. The filter is
// allow-by-default and refuses a small set of syscalls that only widen
// the kernel attack surface or let the agent reach around the sandbox:
// no legitimate agent, build or developer tool needs them. Each is
// refused because of a concrete reason recorded next to it below. This
// is a second layer, as in Docker's and Podman's default profile,
// Flatpak and Codex's own filter; the mount, network and FUSE
// boundaries stay the primary ones.
//
// restrictAgent installs the filter with TSYNC just before the agent is
// started, so it also governs PID 1 (the supervisor). Everything PID 1
// does afterwards -- forking the agent, the proxy/forward bridges over
// AF_UNIX, FUSE, reaping, signalling -- calls none of the refused
// syscalls, so the filter does not get in its way.

// seccomp_data layout. Arguments are 64-bit; only the low 32 bits are
// compared, because the kernel truncates a syscall's register to the
// declared argument width (an ioctl request and a socket family are
// both ints) and a filter on the full 64 bits could be passed with
// high bits set (CVE-2019-10063 in Flatpak). Both ABIs per arch are
// little-endian, so the low half comes first.
const (
	offNr      = 0
	offArch    = 4
	offArg0Low = 16 + 8*0
	offArg1Low = 16 + 8*1
	offArg2Low = 16 + 8*2
	offArg3Low = 16 + 8*3
	// A pointer is not truncated, so prlimit64's new- and old-limit
	// pointers (arg2, arg3) are compared in both halves.
	offArg2High = offArg2Low + 4
	offArg3High = offArg3Low + 4

	// x32SyscallBit marks a syscall made through the x32 ABI; it shares
	// the AUDIT_ARCH_X86_64 value with 64-bit calls and is told apart
	// only by this bit on the number. x32 has its own numbering (nrsX32),
	// filtered with this bit set, so a refused call is refused on x32 too
	// (nono shipped without that, GHSA-vhq2-h2q7-8mmc).
	x32SyscallBit = 0x40000000

	retAllow  = unix.SECCOMP_RET_ALLOW
	retEPERM  = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	retENOSYS = unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)
	// retSkip returns 0 without running the call: an errno of 0.
	retSkip = unix.SECCOMP_RET_ERRNO
	// An unknown architecture is killed, not allowed: on the arches we
	// build for, the only arch values a process can present are the
	// native one and its compat ABIs, all enumerated below. A value
	// outside that set is never a real call we need to serve, and
	// allowing it would reopen the legacy-ABI bypass this filter closes.
	retKill = unix.SECCOMP_RET_KILL_PROCESS
)

// Socket families the agent may open. git, node, python, go and curl
// need AF_UNIX (local sockets), AF_INET/AF_INET6 (the proxy and tcp://
// forwards) and AF_NETLINK (getaddrinfo enumerates interfaces over
// NETLINK_ROUTE). AF_UNSPEC is harmless. Every other family -- AF_VSOCK
// (reaches host services), AF_PACKET (raw frames), and the rest -- is
// refused, matching Flatpak and Codex.
var allowedSocketFamilies = []uint32{
	unix.AF_UNSPEC, unix.AF_UNIX, unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK,
}

// deniedNetlinkProtocols are refused even for an AF_NETLINK socket. The
// agent can make its own user+network namespace, where it is root, and
// from there NETLINK_NETFILTER configures nf_tables and NETLINK_XFRM the
// IPsec state -- both kernel subsystems with a history of
// unprivileged-userns bugs. Everything else (NETLINK_ROUTE, SOCK_DIAG,
// KOBJECT_UEVENT, GENERIC, ...) stays allowed, because getaddrinfo, ss,
// udev and generic-netlink tools need it; a denylist of the two risky
// protocols breaks less than an allowlist of the safe ones would.
var deniedNetlinkProtocols = []uint32{unix.NETLINK_XFRM, unix.NETLINK_NETFILTER}

// Personality values the agent may set. 0x0 is PER_LINUX, the default
// domain. 0x8 is PER_LINUX32, 0x20000 is UNAME26 and 0x20008 is both
// (the set Docker's default profile allows). 0x40000 is ADDR_NO_RANDOMIZE
// and 0x40008 ADDR_NO_RANDOMIZE|PER_LINUX32, which turn off the agent's
// own ASLR and nothing else, so gdb, rr and `setarch -R` work. 0xffffffff
// queries the current personality without changing it. Any other value --
// a switch to another execution domain -- is refused.
var allowedPersonality = []uint32{0x0, 0x8, 0x20000, 0x20008, 0x40000, 0x40008, 0xffffffff}

// terminalIoctls are the ioctl requests refused on every ABI: TIOCSTI
// pushes bytes into a terminal's input as if typed (CVE-2017-5226),
// TIOCLINUX can do the same on a Linux console (CVE-2023-28100). The
// request numbers are architecture-independent.
var terminalIoctls = []uint32{unix.TIOCSTI, unix.TIOCLINUX}

// nrSet is one architecture's syscall numbers for the calls the filter
// treats specially. A zero means the call does not exist on that ABI
// (for example uselib on arm64, kexec_file_load on i386, socketcall
// anywhere but i386) and is skipped.
type nrSet struct {
	// EPERM: refused outright.
	ioURingSetup, ioURingEnter, ioURingRegister uint32
	bpf, perfEventOpen, userfaultfd             uint32
	keyctl, addKey, requestKey                  uint32
	kexecLoad, kexecFileLoad                    uint32
	initModule, finitModule, deleteModule       uint32
	openByHandleAt, quotactl, acct              uint32
	swapon, swapoff, reboot, syslog, uselib     uint32
	lookupDcookie                               uint32
	movePages, migratePages, fanotifyInit       uint32

	// ENOSYS: refused so the caller falls back. io_uring can create
	// sockets (AF_VSOCK included) without a socket() call, so it is kept
	// unavailable on every ABI (Codex's reason); a library that probes
	// it falls back to epoll on ENOSYS.
	//
	// The new mount API can reconfigure the VFS; it is refused only in
	// --strict mode, where the agent also cannot create user namespaces,
	// so it has no legitimate VFS of its own to build. ENOSYS (as
	// Flatpak returns for CVE-2021-41133) makes callers fall back to the
	// classic mount(2) path, which the mount namespace already governs.
	openTree, moveMount, fsopen uint32
	fsconfig, fsmount, fspick   uint32
	mountSetattr                uint32

	// Argument-checked. socketpair takes the family as its first
	// argument like socket, and creates sockets of that family (for
	// example AF_TIPC since Linux 4.12), so it goes through the same
	// family check. socketcall is i386's multiplexer: in --strict mode
	// its SYS_SOCKET/SYS_SOCKETPAIR sub-calls are refused by the call
	// number in arg0. The family is behind a pointer the filter cannot
	// read, so this is coarse -- in --strict mode 32-bit socket creation
	// is refused outright.
	ioctl, socket, socketpair, personality, socketcall uint32

	// Argument-checked in --strict mode only: a change to RLIMIT_CORE is
	// skipped, a read of it and every other limit pass (see the handler
	// in agentFilter).
	setrlimit, prlimit64 uint32
}

// abi is one ABI the filter covers: an AUDIT_ARCH value and the syscall
// numbers for that ABI. x32 shares x86_64's arch value, so the x86_64
// entry also carries x32's own numbers, filtered with x32SyscallBit set.
type abi struct {
	audit uint32
	nrs   nrSet
	x32   *nrSet // x32's numbers under the same arch value, or nil
}

// Syscall numbers per ABI. The native and i386/arm ones are verified
// against golang.org/x/sys's zsysnum tables by TestSyscallNumbers, the
// x32 ones against an excerpt of the kernel's syscall_64.tbl by
// TestX32SyscallNumbers; never hand-edit a number without that
// cross-check.
var (
	nrsAMD64 = nrSet{
		ioURingSetup: 425, ioURingEnter: 426, ioURingRegister: 427,
		bpf: 321, perfEventOpen: 298, userfaultfd: 323,
		keyctl: 250, addKey: 248, requestKey: 249,
		kexecLoad: 246, kexecFileLoad: 320,
		initModule: 175, finitModule: 313, deleteModule: 176,
		openByHandleAt: 304, quotactl: 179, acct: 163,
		swapon: 167, swapoff: 168, reboot: 169, syslog: 103, uselib: 134,
		lookupDcookie: 212,
		movePages:     279, migratePages: 256, fanotifyInit: 300,
		openTree: 428, moveMount: 429, fsopen: 430,
		fsconfig: 431, fsmount: 432, fspick: 433, mountSetattr: 442,
		ioctl: 16, socket: 41, socketpair: 53, personality: 135,
		setrlimit: 160, prlimit64: 302,
	}
	// nrsX32 is the x32 ABI, from arch/x86/entry/syscalls/syscall_64.tbl
	// (https://github.com/torvalds/linux/blob/v6.18/arch/x86/entry/syscalls/syscall_64.tbl):
	// a "common" row has the same number as x86_64, an "x32" row
	// (512-547) is x32's own. kexec_load (528), ioctl (514) and
	// move_pages (533) are x32 rows. uselib (134) is "64"-only and has
	// no x32 entry, so it is 0 here; the kernel returns ENOSYS for it, as
	// for the "64"-only ioctl (16), kexec_load (246) and move_pages (279)
	// numbers, when called through x32. The filter adds x32SyscallBit to
	// every number below.
	nrsX32 = nrSet{
		ioURingSetup: 425, ioURingEnter: 426, ioURingRegister: 427,
		bpf: 321, perfEventOpen: 298, userfaultfd: 323,
		keyctl: 250, addKey: 248, requestKey: 249,
		kexecLoad: 528, kexecFileLoad: 320,
		initModule: 175, finitModule: 313, deleteModule: 176,
		openByHandleAt: 304, quotactl: 179, acct: 163,
		swapon: 167, swapoff: 168, reboot: 169, syslog: 103, uselib: 0, // "64"-only
		lookupDcookie: 212,
		movePages:     533 /* x32 row */, migratePages: 256, fanotifyInit: 300,
		openTree: 428, moveMount: 429, fsopen: 430,
		fsconfig: 431, fsmount: 432, fspick: 433, mountSetattr: 442,
		ioctl: 514, socket: 41, socketpair: 53, personality: 135,
		setrlimit: 160, prlimit64: 302,
	}
	nrs386 = nrSet{
		ioURingSetup: 425, ioURingEnter: 426, ioURingRegister: 427,
		bpf: 357, perfEventOpen: 336, userfaultfd: 374,
		keyctl: 288, addKey: 286, requestKey: 287,
		kexecLoad: 283, kexecFileLoad: 0, // no kexec_file_load on i386
		initModule: 128, finitModule: 350, deleteModule: 129,
		openByHandleAt: 342, quotactl: 131, acct: 51,
		swapon: 87, swapoff: 115, reboot: 88, syslog: 103, uselib: 86,
		lookupDcookie: 253,
		movePages:     317, migratePages: 294, fanotifyInit: 338,
		openTree: 428, moveMount: 429, fsopen: 430,
		fsconfig: 431, fsmount: 432, fspick: 433, mountSetattr: 442,
		ioctl: 54, socket: 359, socketpair: 360, personality: 136, socketcall: 102,
		setrlimit: 75, prlimit64: 340,
	}
	nrsARM64 = nrSet{
		ioURingSetup: 425, ioURingEnter: 426, ioURingRegister: 427,
		bpf: 280, perfEventOpen: 241, userfaultfd: 282,
		keyctl: 219, addKey: 217, requestKey: 218,
		kexecLoad: 104, kexecFileLoad: 294,
		initModule: 105, finitModule: 273, deleteModule: 106,
		openByHandleAt: 265, quotactl: 60, acct: 89,
		swapon: 224, swapoff: 225, reboot: 142, syslog: 116, uselib: 0, // no uselib on arm64
		lookupDcookie: 18,
		movePages:     239, migratePages: 238, fanotifyInit: 262,
		openTree: 428, moveMount: 429, fsopen: 430,
		fsconfig: 431, fsmount: 432, fspick: 433, mountSetattr: 442,
		ioctl: 29, socket: 198, socketpair: 199, personality: 92,
		setrlimit: 164, prlimit64: 261,
	}
	nrsARM = nrSet{
		ioURingSetup: 425, ioURingEnter: 426, ioURingRegister: 427,
		bpf: 386, perfEventOpen: 364, userfaultfd: 388,
		keyctl: 311, addKey: 309, requestKey: 310,
		kexecLoad: 347, kexecFileLoad: 401,
		initModule: 128, finitModule: 379, deleteModule: 129,
		openByHandleAt: 371, quotactl: 131, acct: 51,
		swapon: 87, swapoff: 115, reboot: 88, syslog: 103, uselib: 86,
		lookupDcookie: 249,
		movePages:     344, migratePages: 400, fanotifyInit: 367,
		openTree: 428, moveMount: 429, fsopen: 430,
		fsconfig: 431, fsmount: 432, fspick: 433, mountSetattr: 442,
		ioctl: 54, socket: 281, socketpair: 288, personality: 136,
		setrlimit: 75, prlimit64: 369,
	}
)

// abisFor returns the ABIs to filter for a native architecture: the
// native ABI plus every compat ABI a process of that architecture can
// invoke. An unsupported native arch returns nil: by default no filter
// is installed (the earlier layers still apply), and --strict refuses
// to run (filterFor).
func abisFor(goarch string) []abi {
	switch goarch {
	case "amd64":
		return []abi{
			{audit: unix.AUDIT_ARCH_X86_64, nrs: nrsAMD64, x32: &nrsX32},
			{audit: unix.AUDIT_ARCH_I386, nrs: nrs386},
		}
	case "arm64":
		return []abi{
			{audit: unix.AUDIT_ARCH_AARCH64, nrs: nrsARM64},
			{audit: unix.AUDIT_ARCH_ARM, nrs: nrsARM},
		}
	}
	return nil
}

// eperm and enosys list the numbers refused with each errno for one ABI.
func (n nrSet) eperm() []uint32 {
	return nonzero(
		n.bpf, n.perfEventOpen, n.userfaultfd,
		n.keyctl, n.addKey, n.requestKey,
		n.kexecLoad, n.kexecFileLoad,
		n.initModule, n.finitModule, n.deleteModule,
		n.openByHandleAt, n.quotactl, n.acct,
		n.swapon, n.swapoff, n.reboot, n.syslog, n.uselib,
		n.lookupDcookie,
		n.movePages, n.migratePages, n.fanotifyInit,
	)
}

func (n nrSet) enosys() []uint32 {
	return nonzero(n.ioURingSetup, n.ioURingEnter, n.ioURingRegister)
}

// strictENOSYS is the new mount API, refused only in strict mode.
func (n nrSet) strictENOSYS() []uint32 {
	return nonzero(n.openTree, n.moveMount, n.fsopen, n.fsconfig, n.fsmount, n.fspick, n.mountSetattr)
}

func nonzero(nrs ...uint32) []uint32 {
	var out []uint32
	for _, nr := range nrs {
		if nr != 0 {
			out = append(out, nr)
		}
	}
	return out
}

// bpfBuilder emits a classic-BPF seccomp program, resolving unconditional
// jumps to labels in a second pass. Conditional jumps keep tiny (0/1)
// offsets; every long jump is a BPF_JA with a 32-bit relative K, so the
// program is correct regardless of distance.
type bpfBuilder struct {
	insns   []unix.SockFilter
	jaLabel []string // jaLabel[i] != "" means insns[i] is a JA to that label
	labels  map[string]int
}

func newBuilder() *bpfBuilder {
	return &bpfBuilder{labels: map[string]int{}}
}

func (b *bpfBuilder) emit(in unix.SockFilter) {
	b.insns = append(b.insns, in)
	b.jaLabel = append(b.jaLabel, "")
}

func (b *bpfBuilder) ld(off uint32) {
	b.emit(unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: off})
}

// jeqNext tests A == k; on a match it falls through to the next
// instruction, otherwise it skips it. Paired with jmp it refuses or
// routes one syscall number in two instructions with no distance limit.
func (b *bpfBuilder) jeqNext(k uint32) {
	b.emit(unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: k, Jt: jump(0), Jf: jump(1)})
}

// jneNext tests A != k; when they differ it falls through to the next
// instruction, otherwise it skips it.
func (b *bpfBuilder) jneNext(k uint32) {
	b.emit(unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: k, Jt: jump(1), Jf: jump(0)})
}

// jeqAllow tests A == k; on a match it jumps to the allow label.
func (b *bpfBuilder) jeqAllow(k uint32) {
	b.jeqNext(k)
	b.jmp("allow")
}

// jmp is an unconditional jump to a label, resolved later.
func (b *bpfBuilder) jmp(label string) {
	b.insns = append(b.insns, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JA})
	b.jaLabel = append(b.jaLabel, label)
}

func (b *bpfBuilder) label(name string) { b.labels[name] = len(b.insns) }

func (b *bpfBuilder) ret(k uint32) {
	b.emit(unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: k})
}

func (b *bpfBuilder) resolve() []unix.SockFilter {
	for i := range b.insns {
		if lbl := b.jaLabel[i]; lbl != "" {
			target, ok := b.labels[lbl]
			// Classic seccomp BPF jumps forward only: a target at or
			// before the jump would wrap to a huge offset the kernel
			// rejects with EINVAL. Fail loudly at build time instead.
			if !ok || target <= i {
				panic(fmt.Sprintf("seccomp: label %q resolves to a non-forward jump", lbl))
			}
			b.insns[i].K = uint32(target - (i + 1)) //nolint:gosec // positive (target > i) and below BPF_MAXINSNS
		}
	}
	return b.insns
}

// agentFilter builds the BPF program for the given ABIs. strict adds the
// new-mount-API and socketcall refusals and skips RLIMIT_CORE changes.
func agentFilter(abis []abi, strict bool) []unix.SockFilter {
	b := newBuilder()
	for i, a := range abis {
		next := "kill" // past the last ABI: the arch is unknown
		if i+1 < len(abis) {
			next = fmt.Sprintf("abi%d", i+1)
		}
		b.label(fmt.Sprintf("abi%d", i))
		b.ld(offArch)
		// If this arch matches, enter the block; otherwise jump on.
		b.jneNext(a.audit)
		b.jmp(next)
		b.ld(offNr)

		// The native numbers, then (on x86_64) x32's own with its bit.
		type numbering struct {
			n   nrSet
			bit uint32
		}
		sets := []numbering{{a.nrs, 0}}
		if a.x32 != nil {
			sets = append(sets, numbering{*a.x32, x32SyscallBit})
		}
		for _, s := range sets {
			route := func(nrs []uint32, label string) {
				for _, nr := range nrs {
					b.jeqNext(nr | s.bit)
					b.jmp(label)
				}
			}
			route(s.n.eperm(), "eperm")
			route(s.n.enosys(), "enosys")
			if strict {
				route(s.n.strictENOSYS(), "enosys")
			}
			route(nonzero(s.n.ioctl), "ioctl")
			route(nonzero(s.n.socket, s.n.socketpair), "socket")
			route(nonzero(s.n.personality), "personality")
			if strict {
				// i386 socketcall only; the family is behind a pointer
				// the filter cannot read, so refuse socket creation by
				// the sub-call number instead (coarse, --strict only).
				route(nonzero(s.n.socketcall), "socketcall")
				route(nonzero(s.n.setrlimit), "setrlimit")
				route(nonzero(s.n.prlimit64), "prlimit64")
			}
		}
		b.jmp("allow")
	}

	// Argument handlers, then the shared RET blocks. Classic seccomp BPF
	// allows only forward jumps, so every label a jump targets must come
	// after the jump: the handlers follow the ABI blocks, and the RET
	// blocks the handlers jump to come last.
	b.label("ioctl")
	b.ld(offArg1Low)
	for _, req := range terminalIoctls {
		b.jeqNext(req)
		b.jmp("eperm")
	}
	b.jmp("allow")

	b.label("socket")
	b.ld(offArg0Low) // family
	// AF_NETLINK is allowed, but not every netlink protocol: divert to
	// the protocol check. Every other allowed family passes here.
	b.jeqNext(unix.AF_NETLINK)
	b.jmp("netlinkproto")
	for _, fam := range allowedSocketFamilies {
		if fam == unix.AF_NETLINK {
			continue // diverted above
		}
		b.jeqAllow(fam)
	}
	b.jmp("eperm")

	// netlinkproto refuses the risky netlink protocols (arg2) and allows
	// the rest. It is reached only for an AF_NETLINK socket/socketpair.
	b.label("netlinkproto")
	b.ld(offArg2Low)
	for _, proto := range deniedNetlinkProtocols {
		b.jeqNext(proto)
		b.jmp("eperm")
	}
	b.jmp("allow")

	// socketcall (i386, --strict): refuse the socket-creating sub-calls
	// by the call number in arg0.
	b.label("socketcall")
	b.ld(offArg0Low)
	for _, call := range []uint32{1 /* SYS_SOCKET */, 8 /* SYS_SOCKETPAIR */} {
		b.jeqNext(call)
		b.jmp("eperm")
	}
	b.jmp("allow")

	// setrlimit and prlimit64 (--strict): a change to RLIMIT_CORE is
	// skipped, so it reports success and the limit stays as it is. PID 1
	// sets it to 1 byte, soft and hard (init.go), and the kernel aborts a
	// pipe core_pattern only at exactly 1; any process may lower its own
	// soft limit to 0, and the pipe handler would then run again. A
	// program that sets the limit nearly always wants fewer dumps (gpg and
	// ssh-agent set it to 0 and stop if that fails), and the 1-byte cap
	// already gives it that, so the call is skipped rather than refused.
	// A read stays allowed: glibc's getrlimit, and with it `ulimit -c`, is
	// prlimit64 with no new limit (arg2 NULL). prlimit64 with a new limit
	// and no old one (arg3 NULL) is glibc's setrlimit, and is skipped;
	// with both it is refused, because a skipped call would leave the old
	// limit unfilled.
	b.label("setrlimit")
	b.ld(offArg0Low) // resource
	b.jeqNext(unix.RLIMIT_CORE)
	b.jmp("skip")
	b.jmp("allow")

	b.label("prlimit64")
	b.ld(offArg1Low) // resource
	b.jneNext(unix.RLIMIT_CORE)
	b.jmp("allow")
	for _, off := range []uint32{offArg2Low, offArg2High} { // the new limit
		b.ld(off)
		b.jneNext(0)
		b.jmp("prlimitset")
	}
	b.jmp("allow")
	b.label("prlimitset")
	for _, off := range []uint32{offArg3Low, offArg3High} { // the old limit
		b.ld(off)
		b.jneNext(0)
		b.jmp("eperm")
	}
	b.jmp("skip")

	b.label("personality")
	b.ld(offArg0Low)
	for _, p := range allowedPersonality {
		b.jeqAllow(p)
	}
	b.jmp("eperm")

	b.label("kill")
	b.ret(retKill)
	b.label("allow")
	b.ret(retAllow)
	b.label("eperm")
	b.ret(retEPERM)
	b.label("enosys")
	b.ret(retENOSYS)
	b.label("skip")
	b.ret(retSkip)

	return b.resolve()
}

// jump is a conditional BPF jump offset, which has 8 bits. The builder
// keeps those at 0 or 1 and makes every longer jump a BPF_JA: an offset
// that does not fit is a bug here, and wrapped it would jump somewhere
// else.
func jump(n int) uint8 {
	if n < 0 || n > math.MaxUint8 {
		panic(fmt.Sprintf("seccomp: a jump over %d instructions", n))
	}
	return uint8(n)
}

// filterFor builds the filter for a native architecture. One it has no
// syscall numbers for gets no filter: by default that is nil, and the
// agent runs with no_new_privs only; in --strict mode, where the filter
// is part of what the user asked for, it is an error.
func filterFor(goarch string, strict bool) ([]unix.SockFilter, error) {
	abis := abisFor(goarch)
	if abis == nil {
		if strict {
			return nil, fmt.Errorf("seccomp: no syscall numbers for %s", goarch)
		}
		return nil, nil
	}
	p := agentFilter(abis, strict)
	if len(p) > unix.BPF_MAXINSNS {
		return nil, fmt.Errorf("seccomp: a filter of %d instructions", len(p))
	}
	return p, nil
}

// restrictAgent sets no_new_privs and installs the filter on every
// thread of this process; the agent inherits both across fork and execve.
// TSYNC also copies no_new_privs to the other threads, so one prctl on
// this thread is enough.
func restrictAgent(strict bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	p, err := filterFor(runtime.GOARCH, strict)
	if err != nil {
		return err
	}
	if p == nil {
		return nil // an architecture we have no numbers for: only no_new_privs
	}
	prog := unix.SockFprog{Len: uint16(len(p)), Filter: &p[0]} //nolint:gosec // at most BPF_MAXINSNS, checked in filterFor
	_, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&prog))) //nolint:gosec // seccomp(2) takes a pointer to the program; KeepAlive below
	runtime.KeepAlive(p)
	if e != 0 {
		return fmt.Errorf("seccomp: %w", e)
	}
	return nil
}
