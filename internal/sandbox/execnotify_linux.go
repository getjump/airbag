//go:build linux

package sandbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/getjump/airbag/internal/runtimepolicy"
	"golang.org/x/sys/unix"
)

const (
	execMaxArgs     = 256
	execMaxBytes    = 64 * 1024
	execMaxString   = 4096
	seccompContinue = 1
)

type execData struct {
	Nr   int32
	Arch uint32
	IP   uint64
	Args [6]uint64
}
type execNotification struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  execData
}
type execResponse struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

func execArch() uint32 {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64
	}
	return 0
}

func execFilter(arch uint32, execve, execveat uint32) []unix.SockFilter {
	return []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offArch},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arch, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offNr},
		// Native 64-bit pointer decoding cannot safely decode x32 or compat ABIs.
		{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: x32SyscallBit, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: execve, Jt: 2},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: execveat, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},
	}
}

// ExecInit is a trusted startup helper, before any agent code runs. The
// notifying filter is installed only on this locked thread, then inherited
// by every thread/child of the exec'd agent. PID 1 remains unfiltered.
func ExecInit(path string, argv []string) {
	runtime.LockOSThread()
	unix.CloseOnExec(3)
	if execArch() == 0 {
		fatal("exec policy", errors.New("unsupported architecture"))
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fatal("exec no_new_privs", err)
	}
	filters := execFilter(execArch(), unix.SYS_EXECVE, unix.SYS_EXECVEAT)
	prog := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]} //nolint:gosec // a fixed program of ten instructions
	fd, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, uintptr(unsafe.Pointer(&prog))) //nolint:gosec // seccomp(2) takes a pointer to the program; KeepAlive below
	runtime.KeepAlive(filters)
	if e != 0 {
		fatal("exec seccomp-notify", e)
	}
	if err := unix.Sendmsg(3, []byte{1}, unix.UnixRights(int(fd)), nil, 0); err != nil {
		fatal("send exec listener", err)
	}
	_ = unix.Close(int(fd))
	_ = unix.Close(3)
	if err := syscall.Exec(path, argv, os.Environ()); err != nil { //nolint:gosec // the command the user asked to run, resolved by PID 1
		fatal("exec agent", err)
	}
}

func receiveListener(f *os.File) (int, error) {
	p := []unix.PollFd{{Fd: int32(f.Fd()), Events: unix.POLLIN}} //nolint:gosec // an open descriptor fits an int
	for {
		n, err := unix.Poll(p, 10000)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return -1, err
		}
		if n == 0 {
			return -1, errors.New("exec listener startup timed out")
		}
		break
	}
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, flags, _, err := unix.Recvmsg(int(f.Fd()), buf, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return -1, err
	}
	if n != 1 || buf[0] != 1 || flags&unix.MSG_CTRUNC != 0 {
		return -1, errors.New("exec listener unavailable")
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}
	var rights []int
	for _, message := range messages {
		fds, err := unix.ParseUnixRights(&message)
		if err != nil {
			return -1, err
		}
		rights = append(rights, fds...)
	}
	if len(rights) != 1 {
		for _, fd := range rights {
			_ = unix.Close(fd)
		}
		return -1, errors.New("expected one exec listener")
	}
	return rights[0], nil
}

// notifyIOCTL runs one SECCOMP_IOCTL_NOTIF_* request, which takes a
// pointer to its struct.
func notifyIOCTL[T any](fd int, request uint, arg *T) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(unsafe.Pointer(arg))) //nolint:gosec // the ioctl takes a pointer to arg; KeepAlive below
	runtime.KeepAlive(arg)
	if errno != 0 {
		return errno
	}
	return nil
}
func validNotification(fd int, id uint64) bool {
	return notifyIOCTL(fd, unix.SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == nil
}

// serveExec records attempted invocations, not successful execs. CONTINUE
// necessarily re-reads tracee memory in the kernel: path/argv can race a second
// tracee thread. This is NOT immutable executable identity enforcement.
//
// It returns nil once stop (the read end of a pipe) is readable or closed at
// the other end, or once no task is left under the filter (POLLHUP, Linux
// 5.8+); any other return is an error. NOTIF_RECV is entered only when poll
// reports a notification: a blocked RECV does not return when its fd closes on
// every kernel, so a server waiting there could outlive its session. A
// notification withdrawn in between makes RECV fail with ENOENT, not block.
// After serveExec returns, the caller closes the listener: an execve still
// under the filter then fails with ENOSYS, never runs unchecked.
func serveExec(fd, stop int, check func(runtimepolicy.Request) error) error {
	fds := []unix.PollFd{
		{Fd: int32(fd), Events: unix.POLLIN},   //nolint:gosec // an open descriptor fits an int32
		{Fd: int32(stop), Events: unix.POLLIN}, //nolint:gosec // an open descriptor fits an int32
	}
	for {
		fds[0].Revents, fds[1].Revents = 0, 0
		if _, err := unix.Poll(fds, -1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if fds[1].Revents != 0 {
			return nil
		}
		if fds[0].Revents&unix.POLLNVAL != 0 {
			return errors.New("exec listener closed")
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			if fds[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0 {
				return nil // no task is left under the filter
			}
			continue
		}
		var n execNotification
		err := notifyIOCTL(fd, unix.SECCOMP_IOCTL_NOTIF_RECV, &n)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return err
		}
		if !validNotification(fd, n.ID) {
			continue
		}
		r, readErr := readExec(n)
		if !validNotification(fd, n.ID) {
			continue
		}
		allow := false
		if readErr == nil {
			allow = check(r) == nil
		} else {
			// The error itself is an observed, denied attempt, never an empty allow.
			_ = check(runtimepolicy.Request{Source: "seccomp", Kind: "proc.exec.invalid", Target: fmt.Sprintf("pid:%d", n.PID), PID: n.PID, Detail: readErr.Error()})
		}
		if !validNotification(fd, n.ID) {
			continue
		}
		response := execResponse{ID: n.ID, Error: -int32(unix.EACCES)}
		if allow {
			response.Error = 0
			response.Flags = seccompContinue
		}
		for {
			err = notifyIOCTL(fd, unix.SECCOMP_IOCTL_NOTIF_SEND, &response)
			if errors.Is(err, unix.EINTR) && validNotification(fd, n.ID) {
				continue
			}
			if err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EINTR) {
				return err
			}
			break
		}
	}
}

func readMemory(pid uint32, addr uint64, buf []byte) (int, error) {
	if addr == 0 || addr > uint64(^uintptr(0))-uint64(len(buf)) {
		return 0, errors.New("invalid tracee pointer")
	}
	return unix.ProcessVMReadv(int(pid), []unix.Iovec{{Base: &buf[0], Len: uint64(len(buf))}}, []unix.RemoteIovec{{Base: uintptr(addr), Len: len(buf)}}, 0)
}
func readString(pid uint32, addr uint64) (string, error) {
	var out []byte
	for len(out) < execMaxString {
		// Never read across a page boundary just to look for a trailing NUL.
		size := min(64, execMaxString-len(out), os.Getpagesize()-int(addr%uint64(os.Getpagesize()))) //nolint:gosec // the page size is positive, the remainder below it
		buf := make([]byte, size)
		n, err := readMemory(pid, addr, buf)
		if err != nil {
			return "", err
		}
		if n == 0 {
			return "", errors.New("short tracee read")
		}
		for i, b := range buf[:n] {
			if b == 0 {
				return string(append(out, buf[:i]...)), nil
			}
		}
		out = append(out, buf[:n]...)
		addr += uint64(n) //nolint:gosec // a byte count, never negative
	}
	return "", errors.New("exec string exceeds audit limit")
}
func readArgv(pid uint32, addr uint64) ([]string, error) {
	var out []string
	total := 0
	// Linux accepts a NULL argv pointer; normalize it to an empty list.
	if addr == 0 {
		return []string{}, nil
	}
	for i := 0; i <= execMaxArgs; i++ {
		var buf [8]byte
		n, err := readMemory(pid, addr+uint64(i*8), buf[:])
		if err != nil {
			return nil, err
		}
		if n != 8 {
			return nil, errors.New("short argv pointer")
		}
		ptr := binary.LittleEndian.Uint64(buf[:])
		if ptr == 0 {
			return out, nil
		}
		if i == execMaxArgs {
			return nil, errors.New("argv exceeds audit limit")
		}
		arg, err := readString(pid, ptr)
		if err != nil {
			return nil, err
		}
		total += len(arg) + 1
		if total > execMaxBytes {
			return nil, errors.New("argv exceeds audit byte limit")
		}
		out = append(out, arg)
	}
	return nil, errors.New("unterminated argv")
}
func readExec(n execNotification) (runtimepolicy.Request, error) {
	r := runtimepolicy.Request{Source: "seccomp", Kind: "proc.exec", PID: n.PID, Detail: "execve"}
	if n.Data.Arch != execArch() {
		return r, errors.New("unsupported exec ABI")
	}
	pathPtr, argvPtr := n.Data.Args[0], n.Data.Args[1]
	dirfd := unix.AT_FDCWD
	flags := uint64(0)
	if n.Data.Nr == int32(unix.SYS_EXECVEAT) {
		r.Detail = "execveat"
		dirfd = int(int32(n.Data.Args[0])) //nolint:gosec // the kernel reads dirfd as an int: its low 32 bits
		pathPtr, argvPtr = n.Data.Args[1], n.Data.Args[2]
		flags = n.Data.Args[4]
	} else if n.Data.Nr != int32(unix.SYS_EXECVE) {
		return r, errors.New("unexpected exec syscall")
	}
	name, err := readString(n.PID, pathPtr)
	if err != nil {
		return r, err
	}
	r.Argv, err = readArgv(n.PID, argvPtr)
	if err != nil {
		return r, err
	}
	if name == "" && flags&unix.AT_EMPTY_PATH == 0 {
		return r, errors.New("empty executable pathname")
	}
	r.Target, err = execTarget(fmt.Sprintf("/proc/%d", n.PID), dirfd, name)
	return r, err
}

// execTarget names the executable as the caller at proc (its /proc
// directory) sees it. The kernel writes /proc links from PID 1's root, so a
// caller in a chroot would otherwise be checked under PID 1's path to its
// jail, which a rule on the path in the jail never matches. A base outside
// the caller's root (a cwd or descriptor kept across chroot) has no such
// name: the exec is refused as invalid.
func execTarget(proc string, dirfd int, name string) (string, error) {
	root, err := openExecRoot(proc + "/root")
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(root.fd) }()
	if name == "" {
		link, err := os.Readlink(fmt.Sprintf("%s/fd/%d", proc, dirfd))
		if err != nil {
			return "", err
		}
		return root.inside(link)
	}
	if !filepath.IsAbs(name) {
		base := proc + "/cwd"
		if dirfd != unix.AT_FDCWD {
			base = fmt.Sprintf("%s/fd/%d", proc, dirfd)
		}
		link, err := os.Readlink(base)
		if err != nil {
			return "", err
		}
		dir, err := root.inside(link)
		if err != nil {
			return "", err
		}
		name = dir + "/" + name
	}
	return root.resolve(name)
}

// execRoot is the caller's root, opened once, and PID 1's path to it.
type execRoot struct {
	fd   int
	path string
}

func openExecRoot(dir string) (execRoot, error) {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return execRoot{}, err
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		_ = unix.Close(fd)
		return execRoot{}, err
	}
	return execRoot{fd: fd, path: path}, nil
}

// inside turns a path as PID 1 sees it into the caller's path, or refuses
// one outside the caller's root.
func (r execRoot) inside(link string) (string, error) {
	rel, err := filepath.Rel(r.path, link)
	if err != nil || !filepath.IsAbs(link) || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("exec path %q is outside the caller's root", link)
	}
	return filepath.Join("/", rel), nil
}

// resolve follows symlinks in name inside the caller's root, as the
// kernel will: an absolute link or ".." never leaves it, which reading
// /proc/PID/root as a plain path does not ensure. A name that does not
// resolve is checked as written: the kernel fails a missing file or a
// symlink loop too. A magic link (/proc/self/exe) is not followed, since
// PID 1 would follow its own, and is checked as written as well.
func (r execRoot) resolve(name string) (string, error) {
	how := unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS}
	fd, err := unix.Openat2(r.fd, name, &how)
	// EAGAIN: a rename or mount raced the lookup; the kernel asks for a retry.
	for i := 0; i < 8 && errors.Is(err, unix.EAGAIN); i++ {
		fd, err = unix.Openat2(r.fd, name, &how)
	}
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		return filepath.Clean(name), nil
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(fd) }()
	link, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return "", err
	}
	return r.inside(link)
}
