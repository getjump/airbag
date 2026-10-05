//go:build linux

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Guest runs only in a prepared rootfs. The host never reads its session
// metadata through a guest mount. This entry point is not a policy authority.
func Guest(args []string) int {
	if len(args) == 1 && args[0] == "userns" {
		return 0 // checkNoUserNamespaces's child: it exists only if one was created
	}
	b, err := os.ReadFile(guestConfigPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "airbag guest:", err)
		return 125
	}
	var c guestConfig
	if err := json.Unmarshal(b, &c); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 125
	}
	if c.UID < 0 || c.GID < 0 || int64(c.UID) > math.MaxUint32 || int64(c.GID) > math.MaxUint32 {
		return 125
	}
	if len(args) == 1 && args[0] == "exec" {
		return guestExec(c)
	}
	// The helper holds the relays, as native's PID 1 does, and is made
	// non-dumpable as it is: defense in depth against the agent's ptrace
	// and /proc access.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		fmt.Fprintln(os.Stderr, "airbag guest: protect helper:", err)
		return 125
	}
	vm := c.Backend == "microvm"
	code := 125
	if err := guestSetup(c, vm); err != nil {
		fmt.Fprintln(os.Stderr, "airbag guest setup:", err)
	} else {
		code = guestAgent(c, vm)
	}
	if vm {
		// Kill agent descendants before reading the exported tree; no process may
		// keep mutating it after the main command exits.
		_ = syscall.Kill(-1, syscall.SIGKILL)
		conn, err := dialVsock(4002)
		if err == nil {
			_, err = conn.Write([]byte{byte(code)})
			if err == nil {
				err = exportWorkspace(c.Workspace, conn)
			}
			_ = conn.Close()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "airbag guest export:", err)
		}
		unix.Sync()
		_ = unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
		return 125
	}
	return code
}

func guestSetup(c guestConfig, vm bool) error {
	if vm {
		if os.Getpid() != 1 {
			return fmt.Errorf("microVM guest must be PID 1")
		}
		for _, m := range []struct{ source, target, kind string }{{"devtmpfs", "/dev", "devtmpfs"}, {"proc", "/proc", "proc"}, {"sysfs", "/sys", "sysfs"}, {"tmpfs", "/tmp", "tmpfs"}, {"tmpfs", "/home/agent", "tmpfs"}} {
			if err := unix.Mount(m.source, m.target, m.kind, unix.MS_NOSUID, ""); err != nil && !errors.Is(err, unix.EBUSY) {
				return err
			}
		}
		if err := unix.Mount("/dev/vdb", c.Workspace, "ext4", unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
			return err
		}
		// As native hides them: reads into the kernel the filter does not
		// cover (the kernel log, a userfaultfd without the syscall).
		for _, p := range []string{"/dev/kmsg", "/dev/userfaultfd"} {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if c.GeneratedRecoveryDir {
			if err := os.Remove(filepath.Join(c.Workspace, "lost+found")); err != nil {
				return fmt.Errorf("remove generated recovery directory: %w", err)
			}
		}
		work, err := os.OpenRoot(c.Workspace)
		if err != nil {
			return err
		}
		defer func() { _ = work.Close() }()
		if err := filepath.WalkDir(c.Workspace, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(c.Workspace, path)
			if err != nil {
				return err
			}
			return work.Lchown(rel, c.UID, c.GID)
		}); err != nil {
			return err
		}
		if err := os.Chown("/home/agent", c.UID, c.GID); err != nil {
			return err
		}
		if err := os.Chmod("/tmp", 0o1777); err != nil { //nolint:gosec // private guest temporary directory
			return err
		}
		if err := os.WriteFile("/proc/sys/user/max_user_namespaces", []byte("0"), 0); err != nil {
			return err
		}
		if err := loopbackUp(); err != nil {
			return err
		}
		// /run contains immutable code/config; only this socket directory is mutable.
		if err := unix.Mount("tmpfs", "/run/airbag/sockets", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
			return err
		}
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", "/run/airbag/sockets/ctl.sock")
		if err != nil {
			return err
		}
		if err := os.Chmod("/run/airbag/sockets/ctl.sock", 0o666); err != nil { //nolint:gosec // scoped policy channel, private guest only
			_ = l.Close()
			return err
		}
		go serveRelay(l, func() (net.Conn, error) { return dialVsock(4001) })
	}
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", ProxyAddr)
	if err != nil {
		return err
	}
	dial := func() (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(context.Background(), "unix", proxySockInside)
	}
	if vm {
		dial = func() (net.Conn, error) { return dialVsock(4000) }
	}
	go serveRelay(l, dial)
	return nil
}

func guestAgent(c guestConfig, vm bool) int {
	cmd := exec.CommandContext(context.Background(), "/run/airbag/bin/airbag", GuestArg, "exec")
	cmd.Env, cmd.Dir = c.Env, c.Cwd
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if vm {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(c.UID), Gid: uint32(c.GID), NoSetGroups: false} //nolint:gosec // host IDs validated in Guest before conversion
	}
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if exit.ExitCode() < 0 {
			return 128
		}
		return exit.ExitCode()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 126
	}
	return 0
}

func guestExec(c guestConfig) int {
	if len(c.Argv) == 0 {
		return 125
	}
	// Core dumps capped at 1 byte and inherited descriptors closed on
	// exec, as runAgent does; --strict stops the run if the cap fails.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 1, Max: 1}); err != nil {
		if c.Strict {
			fmt.Fprintln(os.Stderr, "airbag guest: limit core dumps:", err)
			return 125
		}
		fmt.Fprintf(os.Stderr, "airbag: warning: could not limit core dumps: %v\n", err)
	}
	closeInheritedFDs()
	// --strict adds the strict filter, as for native. Unlike native's
	// default, a filter that cannot be installed always stops the run.
	if err := restrictAgent(c.Strict); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 125
	}
	if err := restrictGuest(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 125
	}
	if err := checkNoUserNamespaces(); err != nil {
		fmt.Fprintln(os.Stderr, "airbag guest:", err)
		return 125
	}
	path := c.Argv[0]
	if !strings.Contains(path, "/") {
		resolved, err := lookPath(path, c.Env)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 127
		}
		path = resolved
	}
	if err := syscall.Exec(path, c.Argv, c.Env); err != nil { //nolint:gosec // user command inside selected execution boundary
		fmt.Fprintln(os.Stderr, err)
		return 126
	}
	return 0
}

// guestFilter is stacked on the agent's filter in an optional runtime.
// It refuses clone3 with ENOSYS: its flags sit behind a pointer no filter
// can read, so it could create the user namespace that clone is refused
// (gVisor's OCI filter); glibc falls back to clone only on ENOSYS. clone3
// is 435 on every ABI abisFor covers, x32 with its bit.
func guestFilter() []unix.SockFilter {
	b := newBuilder()
	b.ld(offNr)
	for _, nr := range []uint32{unix.SYS_CLONE3, unix.SYS_CLONE3 | x32SyscallBit} {
		b.jeqNext(nr)
		b.jmp("enosys")
	}
	b.ret(retAllow)
	b.label("enosys")
	b.ret(retENOSYS)
	return b.resolve()
}

// restrictGuest installs guestFilter after restrictAgent, which has set
// no_new_privs.
func restrictGuest() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	p := guestFilter()
	prog := unix.SockFprog{Len: uint16(len(p)), Filter: &p[0]} //nolint:gosec // a fixed program of a few instructions
	_, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&prog))) //nolint:gosec // seccomp(2) takes a pointer to the program; KeepAlive below
	runtime.KeepAlive(p)
	if e != 0 {
		return fmt.Errorf("seccomp: %w", e)
	}
	return nil
}

// checkNoUserNamespaces runs under the agent's filters, just before its
// exec: clone3 must be refused by guestFilter (the kernel would answer
// EINVAL to these arguments), and a child must not start in a new user
// namespace (gVisor's OCI filter, the microVM's max_user_namespaces).
// Both runtimes promise what --strict gives native; a runtime that
// ignores a limit stops the run instead of leaving it open.
func checkNoUserNamespaces() error {
	if _, _, e := unix.RawSyscall(unix.SYS_CLONE3, 0, 0, 0); e != unix.ENOSYS {
		return fmt.Errorf("clone3 is not filtered (%w); refusing to start the agent", e)
	}
	cmd := exec.CommandContext(context.Background(), "/run/airbag/bin/airbag", GuestArg, "userns")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}
	if err := cmd.Start(); err != nil {
		return nil //nolint:nilerr // refused: what the check wants
	}
	_ = cmd.Wait()
	return errors.New("a process can still create a user namespace; refusing to start the agent")
}

func serveRelay(l net.Listener, dial func() (net.Conn, error)) {
	for {
		client, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer client.Close()
			target, err := dial()
			if err != nil {
				return
			}
			defer target.Close()
			done := make(chan struct{})
			go func() { _, _ = io.Copy(target, client); _ = target.Close(); close(done) }()
			_, _ = io.Copy(client, target)
			_ = client.Close()
			_ = target.Close()
			<-done
		}()
	}
}

func dialVsock(port uint32) (net.Conn, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: 2, Port: port}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "vsock")
	// net.FileConn does not recognize AF_VSOCK. A pollable os.File provides the
	// same stream to the bounded export and the two scoped transport relays.
	return &vsockConn{File: file}, nil
}

type vsockConn struct{ *os.File }

func (c *vsockConn) LocalAddr() net.Addr                { return vsockAddr("guest") }
func (c *vsockConn) RemoteAddr() net.Addr               { return vsockAddr("host") }
func (c *vsockConn) SetDeadline(t time.Time) error      { return c.File.SetDeadline(t) }
func (c *vsockConn) SetReadDeadline(t time.Time) error  { return c.File.SetReadDeadline(t) }
func (c *vsockConn) SetWriteDeadline(t time.Time) error { return c.File.SetWriteDeadline(t) }

type vsockAddr string

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return string(a) }
