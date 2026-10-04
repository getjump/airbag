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
		{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: x32Bit, Jf: 1},
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
	prog := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	fd, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, uintptr(unsafe.Pointer(&prog)))
	runtime.KeepAlive(filters)
	if e != 0 {
		fatal("exec seccomp-notify", e)
	}
	if err := unix.Sendmsg(3, []byte{1}, unix.UnixRights(int(fd)), nil, 0); err != nil {
		fatal("send exec listener", err)
	}
	unix.Close(int(fd))
	unix.Close(3)
	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		fatal("exec agent", err)
	}
}

func receiveListener(f *os.File) (int, error) {
	p := []unix.PollFd{{Fd: int32(f.Fd()), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(p, 10000)
		if err == unix.EINTR {
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
			unix.Close(fd)
		}
		return -1, errors.New("expected one exec listener")
	}
	return rights[0], nil
}

func notifyIOCTL(fd int, request uint, ptr unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(ptr))
	runtime.KeepAlive(ptr)
	if errno != 0 {
		return errno
	}
	return nil
}
func validNotification(fd int, id uint64) bool {
	return notifyIOCTL(fd, unix.SECCOMP_IOCTL_NOTIF_ID_VALID, unsafe.Pointer(&id)) == nil
}

// serveExec records attempted invocations, not successful execs. CONTINUE
// necessarily re-reads tracee memory in the kernel: path/argv can race a second
// tracee thread. This is NOT immutable executable identity enforcement.
func serveExec(fd int, check func(runtimepolicy.Request) error) error {
	for {
		var n execNotification
		err := notifyIOCTL(fd, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&n))
		if err == unix.EINTR || err == unix.ENOENT {
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
			err = notifyIOCTL(fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&response))
			if err == unix.EINTR && validNotification(fd, n.ID) {
				continue
			}
			if err != nil && err != unix.ENOENT && err != unix.EINTR {
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
		size := min(64, execMaxString-len(out), os.Getpagesize()-int(addr%uint64(os.Getpagesize())))
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
		addr += uint64(n)
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
		dirfd = int(int32(n.Data.Args[0]))
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
	prefix := fmt.Sprintf("/proc/%d", n.PID)
	if name == "" {
		if flags&unix.AT_EMPTY_PATH == 0 {
			return r, errors.New("empty executable pathname")
		}
		r.Target, err = os.Readlink(fmt.Sprintf("%s/fd/%d", prefix, dirfd))
		return r, err
	}
	if !filepath.IsAbs(name) {
		base := prefix + "/cwd"
		if dirfd != unix.AT_FDCWD {
			base = fmt.Sprintf("%s/fd/%d", prefix, dirfd)
		}
		dir, err := os.Readlink(base)
		if err != nil {
			return r, err
		}
		name = filepath.Join(dir, name)
	}
	r.Target = filepath.Clean(name)
	// Resolve normal symlink aliases in the caller's root, including chroots.
	// Failure is an exec attempt too (ENOENT is decided by the kernel later).
	if resolved, err := filepath.EvalSymlinks(prefix + "/root" + r.Target); err == nil {
		root, err := os.Readlink(prefix + "/root")
		if err == nil {
			if rel, err := filepath.Rel(root, resolved); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
				r.Target = "/" + rel
			}
		}
	}
	return r, nil
}
