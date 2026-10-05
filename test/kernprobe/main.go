//go:build linux

// Command kernprobe makes each kernel-surface syscall the sandbox
// refuses and prints the result as "name=ERRNO" (or "name=OK" when the
// call unexpectedly succeeded). test/kernel-e2e.sh runs it inside a
// session and checks each verdict. It makes raw syscalls by number, so
// the ABI is exactly the binary's: build it for GOARCH=386 to drive the
// i386 compat ABI without going through a C library's socketcall.
package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// result turns a syscall return into a short errno name the test greps.
func result(errno unix.Errno) string {
	switch errno {
	case 0:
		return "OK"
	case unix.EPERM:
		return "EPERM"
	case unix.ENOSYS:
		return "ENOSYS"
	default:
		return errno.Error()
	}
}

func socketFamily(fam int) string {
	fd, _, e := unix.Syscall(unix.SYS_SOCKET, uintptr(fam), uintptr(unix.SOCK_DGRAM), 0)
	if e == 0 {
		_ = unix.Close(int(fd))
	}
	return result(e)
}

//nolint:gosec // unsafe: socketpair(2) writes the two fds through a pointer
func socketpairFamily(fam int) string {
	var fds [2]int32
	_, _, e := unix.Syscall6(unix.SYS_SOCKETPAIR, uintptr(fam), uintptr(unix.SOCK_DGRAM), 0, uintptr(unsafe.Pointer(&fds)), 0, 0)
	if e == 0 {
		_ = unix.Close(int(fds[0]))
		_ = unix.Close(int(fds[1]))
	}
	return result(e)
}

// netlinkProto opens an AF_NETLINK socket of the given protocol.
func netlinkProto(proto int) string {
	fd, _, e := unix.Syscall(unix.SYS_SOCKET, uintptr(unix.AF_NETLINK), uintptr(unix.SOCK_RAW), uintptr(proto))
	if e == 0 {
		_ = unix.Close(int(fd))
	}
	return result(e)
}

//nolint:gosec // unsafe: each probe passes the kernel a pointer to a zeroed argument struct
func main() {
	probes := map[string]func() string{
		"io_uring_setup": func() string {
			var params [120]byte // >= sizeof(struct io_uring_params)
			_, _, e := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params)), 0)
			return result(e)
		},
		"bpf": func() string {
			var attr [128]byte
			_, _, e := unix.Syscall(unix.SYS_BPF, 0 /*BPF_MAP_CREATE*/, uintptr(unsafe.Pointer(&attr)), uintptr(len(attr)))
			return result(e)
		},
		"perf_event_open": func() string {
			var attr [128]byte // struct perf_event_attr
			_, _, e := unix.Syscall6(unix.SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(&attr)), 0, ^uintptr(0), ^uintptr(0), 0, 0)
			return result(e)
		},
		"add_key": func() string {
			typ := []byte("user\x00")
			desc := []byte("airbag-probe\x00")
			payload := []byte("x")
			_, _, e := unix.Syscall6(unix.SYS_ADD_KEY,
				uintptr(unsafe.Pointer(&typ[0])), uintptr(unsafe.Pointer(&desc[0])),
				uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
				^uintptr(0) /*KEY_SPEC_PROCESS_KEYRING*/, 0)
			return result(e)
		},
		"userfaultfd": func() string {
			// UFFD_USER_MODE_ONLY (0x1): a user-mode-only userfaultfd
			// needs no privilege, so outside the filter this succeeds
			// even where vm.unprivileged_userfaultfd=0. EPERM then can
			// only come from the filter.
			const uffdUserModeOnly = 0x1
			fd, _, e := unix.Syscall(unix.SYS_USERFAULTFD, uintptr(unix.O_CLOEXEC|uffdUserModeOnly), 0, 0)
			if e == 0 {
				_ = unix.Close(int(fd))
			}
			return result(e)
		},
		// fsopen is the new mount API, refused with ENOSYS in --strict
		// mode only; outside strict the kernel handles it.
		"fsopen": func() string {
			name := []byte("ext4\x00")
			fd, _, e := unix.Syscall(unix.SYS_FSOPEN, uintptr(unsafe.Pointer(&name[0])), 0, 0)
			if e == 0 {
				_ = unix.Close(int(fd))
			}
			return result(e)
		},
		"socket_vsock":  func() string { return socketFamily(unix.AF_VSOCK) },
		"socket_packet": func() string { return socketFamily(unix.AF_PACKET) },
		// AF_ALG needs no privilege, so outside the filter it succeeds;
		// EPERM inside therefore comes from the filter, not from a
		// missing capability the way AF_PACKET's would.
		"socket_alg": func() string { return socketFamily(unix.AF_ALG) },
		// socket(AF_NETLINK, *, NETLINK_NETFILTER) must be refused, while
		// NETLINK_ROUTE keeps working.
		"netlink_netfilter": func() string { return netlinkProto(unix.NETLINK_NETFILTER) },
		"netlink_route":     func() string { return netlinkProto(unix.NETLINK_ROUTE) },
		// socketcall is i386-only; on other ABIs this returns "n/a".
		"socketcall_socket": socketcallSocket,
		// socketpair creates sockets of the family it is given (AF_TIPC
		// supports it since Linux 4.12), so it is family-checked too. The
		// kernel itself never answers EPERM here (EAFNOSUPPORT or
		// EOPNOTSUPP at most), so EPERM can only come from the filter.
		"socketpair_tipc": func() string { return socketpairFamily(unix.AF_TIPC) },
		"socketpair_unix": func() string { return socketpairFamily(unix.AF_UNIX) },
		// ptrace of PID 1 (the supervisor) must fail: the agent's user
		// namespace has no CAP_SYS_PTRACE over PID 1 in the parent
		// namespace, and dumpable=0 blocks it as well. ptrace itself
		// stays allowed, so a success here would be a real exposure.
		"ptrace_pid1": func() string {
			_, _, e := unix.Syscall6(unix.SYS_PTRACE, uintptr(unix.PTRACE_ATTACH), 1, 0, 0, 0, 0)
			return result(e)
		},
	}

	// With an argument, run just that probe (quiet, value only); with
	// none, run all and label each.
	if len(os.Args) > 1 {
		f, ok := probes[os.Args[1]]
		if !ok {
			fmt.Fprintln(os.Stderr, "unknown probe", os.Args[1])
			os.Exit(2)
		}
		fmt.Println(f())
		return
	}
	for _, name := range []string{
		"io_uring_setup", "bpf", "perf_event_open", "add_key",
		"userfaultfd", "socket_vsock", "socket_packet", "socket_alg",
		"socketpair_tipc", "socketpair_unix",
		"netlink_netfilter", "netlink_route",
	} {
		fmt.Printf("%s=%s\n", name, probes[name]())
	}
}
