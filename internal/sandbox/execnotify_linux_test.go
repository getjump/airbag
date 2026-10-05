//go:build linux

package sandbox

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/runtimepolicy"
	"golang.org/x/sys/unix"
)

func TestExecFilter(t *testing.T) {
	for _, abi := range []struct{ arch, execve, execveat uint32 }{{unix.AUDIT_ARCH_X86_64, 59, 322}, {unix.AUDIT_ARCH_AARCH64, 221, 281}} {
		p := execFilter(abi.arch, abi.execve, abi.execveat)
		for _, nr := range []uint32{abi.execve, abi.execveat} {
			if got := runBPF(t, p, seccompData(abi.arch, nr, 0, 0)); got != unix.SECCOMP_RET_USER_NOTIF {
				t.Fatalf("exec passed: %#x", got)
			}
		}
		if got := runBPF(t, p, seccompData(abi.arch, 1, 0, 0)); got != unix.SECCOMP_RET_ALLOW {
			t.Fatal("non-exec blocked")
		}
		for _, d := range [][]byte{seccompData(unix.AUDIT_ARCH_I386, 11, 0, 0), seccompData(abi.arch, x32SyscallBit|abi.execve, 0, 0)} {
			if got := runBPF(t, p, d); got != unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS) {
				t.Fatal("compat ABI bypass")
			}
		}
	}
}

func TestExecNotifyHelper(t *testing.T) {
	if os.Getenv("AIRBAG_TEST_NOTIFY_HELPER") != "1" {
		return
	}
	ExecInit("/bin/sh", []string{"sh", "-c", os.Getenv("AIRBAG_TEST_NOTIFY_COMMAND")})
}

// startNotifyHelper runs this test binary as the exec helper with the
// shell command given, and returns it with the filter's listener.
func startNotifyHelper(t *testing.T, command string) (*exec.Cmd, *bytes.Buffer, int) {
	t.Helper()
	if execArch() == 0 {
		t.Skip("unsupported architecture")
	}
	host, child, err := socketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()
	defer func() { _ = child.Close() }()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestExecNotifyHelper$") //nolint:gosec // this test binary, as the helper
	cmd.Env = append(os.Environ(), "AIRBAG_TEST_NOTIFY_HELPER=1", "AIRBAG_TEST_NOTIFY_COMMAND="+command)
	cmd.ExtraFiles = []*os.File{child}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = child.Close()
	listener, err := receiveListener(host)
	if err != nil {
		_ = cmd.Wait()
		t.Fatalf("listener: %v: %s", err, output.String())
	}
	return cmd, &output, listener
}

// serveUntilStopped runs serveExec in a goroutine. The returned stop
// closes the pipe, waits for serveExec to return and then closes the
// listener, so no goroutine outlives the test; it reports how serveExec
// ended.
func serveUntilStopped(t *testing.T, listener int, check func(runtimepolicy.Request) error) (stop func() error) {
	t.Helper()
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- serveExec(listener, pipe[0], check) }()
	var once sync.Once
	var result error
	stop = func() error {
		once.Do(func() {
			_ = unix.Close(pipe[1])
			result = <-served
			_ = unix.Close(pipe[0])
			_ = unix.Close(listener)
		})
		return result
	}
	t.Cleanup(func() { _ = stop() })
	return stop
}

// This exercises real kernel notifications and tracee memory, without needing
// user namespaces or /dev/fuse. The sandbox E2E adds those layers in CI.
func TestExecNotifyKernel(t *testing.T) {
	sentinel := filepath.Join(t.TempDir(), "should-not-exist")
	cmd, output, listener := startNotifyHelper(t, "exec /usr/bin/touch "+sentinel)
	var mu sync.Mutex
	var events []runtimepolicy.Request
	stop := serveUntilStopped(t, listener, func(r runtimepolicy.Request) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, r)
		if filepath.Base(r.Target) == "touch" {
			return fmt.Errorf("denied touch")
		}
		return nil
	})
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("exec notification hung")
	}
	if err := stop(); err != nil {
		t.Fatalf("serveExec: %v", err)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatal("denied executable ran")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) == 1 && events[0].Kind == "proc.exec.invalid" && events[0].Detail == unix.EPERM.Error() && os.Getenv("CI") != "true" {
		t.Skip("this container blocks process_vm_readv; kernel E2E runs in CI")
	}
	if len(events) != 2 || events[0].Kind != "proc.exec" || filepath.Base(events[1].Target) != "touch" || len(events[1].Argv) != 2 || events[1].Argv[1] != sentinel {
		t.Fatalf("wrong kernel events: %+v; %s", events, output.String())
	}
}

// An exec the client refuses as too large for one frame never reached the
// log; it is logged as an invalid attempt instead, without its argv.
func TestExecNotifyLogsOversizedAttempt(t *testing.T) {
	sentinel := filepath.Join(t.TempDir(), "should-not-exist")
	cmd, output, listener := startNotifyHelper(t, "exec /usr/bin/touch "+sentinel)
	var mu sync.Mutex
	var events []runtimepolicy.Request
	stop := serveUntilStopped(t, listener, func(r runtimepolicy.Request) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, r)
		if filepath.Base(r.Target) == "touch" {
			return fmt.Errorf("%w: test", runtimepolicy.ErrFrameTooLarge)
		}
		return nil
	})
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("exec notification hung")
	}
	if err := stop(); err != nil {
		t.Fatalf("serveExec: %v", err)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatal("refused executable ran")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) == 1 && events[0].Kind == "proc.exec.invalid" && events[0].Detail == unix.EPERM.Error() && os.Getenv("CI") != "true" {
		t.Skip("this container blocks process_vm_readv; kernel E2E runs in CI")
	}
	last := events[len(events)-1]
	if len(events) != 3 || last.Kind != "proc.exec.invalid" || last.Argv != nil || !strings.Contains(last.Detail, runtimepolicy.ErrFrameTooLarge.Error()) {
		t.Fatalf("oversized exec not logged as invalid: %+v; %s", events, output.String())
	}
}

// The server stops on its pipe while a task is still under the filter
// and idle, where a blocked NOTIF_RECV would never return; an execve
// after that gets ENOSYS, not an unchecked run.
func TestExecNotifyStopsWhileTaskLives(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	ran := filepath.Join(t.TempDir(), "ran")
	// sh is exec'd under the filter (allowed), then waits for the go-ahead
	// and tries one more exec once the server has stopped.
	cmd, output, listener := startNotifyHelper(t, "while [ ! -e "+ready+" ]; do :; done; /usr/bin/touch "+ran+"; echo rc=$?")
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-done
	})
	stop := serveUntilStopped(t, listener, func(runtimepolicy.Request) error { return nil })
	time.Sleep(200 * time.Millisecond) // sh is past its own exec and spinning
	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("serveExec: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveExec did not stop while a task was under the filter")
	}
	if err := os.WriteFile(ready, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("helper did not finish")
	}
	if _, err := os.Stat(ran); !os.IsNotExist(err) {
		t.Fatalf("an execve ran after the server stopped: %s", output.String())
	}
	if !strings.Contains(output.String(), "rc=") || strings.Contains(output.String(), "rc=0") {
		t.Fatalf("the execve after stop did not fail: %s", output.String())
	}
}

// A caller in a chroot names its executable in its own root. proc stands in
// for /proc/PID: root, cwd and fd links as the kernel writes them, from
// PID 1's root.
func TestExecTargetInCallerRoot(t *testing.T) {
	top, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	jail, outside, proc := filepath.Join(top, "jail"), filepath.Join(top, "outside"), filepath.Join(top, "proc")
	for _, d := range []string{jail + "/bin", jail + "/sub", outside, proc + "/fd"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(jail+"/bin/tool", []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		jail + "/bin/alias":    "/bin/tool", // absolute, so in the jail's root
		jail + "/sub/relative": "../bin/tool",
		proc + "/root":         jail,
		proc + "/cwd":          jail + "/bin",
		proc + "/fd/7":         jail + "/sub",
		proc + "/fd/8":         jail + "/bin/tool",
		proc + "/fd/9":         outside,
		proc + "/fd/10":        jail + "x/bin/tool",
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		dirfd int
		name  string
	}{
		{unix.AT_FDCWD, "tool"},
		{unix.AT_FDCWD, "/bin/tool"},
		{unix.AT_FDCWD, "/bin/alias"},
		{unix.AT_FDCWD, "../../../bin/alias"},
		{7, "relative"},
		{7, "../bin/alias"},
		{8, ""},
	} {
		if got, err := execTarget(proc, c.dirfd, c.name); err != nil || got != "/bin/tool" {
			t.Errorf("execTarget(%d, %q) = %q, %v; want /bin/tool", c.dirfd, c.name, got, err)
		}
	}
	// The kernel fails these; they are checked as written, in the jail.
	if got, err := execTarget(proc, unix.AT_FDCWD, "missing"); err != nil || got != "/bin/missing" {
		t.Errorf("missing file: %q, %v", got, err)
	}
	// A base outside the root has no name in it.
	for _, c := range []struct {
		dirfd int
		name  string
	}{{9, "tool"}, {9, ""}, {10, ""}} {
		if got, err := execTarget(proc, c.dirfd, c.name); err == nil {
			t.Errorf("execTarget(%d, %q) = %q outside the caller's root", c.dirfd, c.name, got)
		}
	}
	if err := os.Remove(proc + "/cwd"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, proc+"/cwd"); err != nil {
		t.Fatal(err)
	}
	if got, err := execTarget(proc, unix.AT_FDCWD, "tool"); err == nil {
		t.Errorf("cwd outside the caller's root: %q", got)
	}
	if got, err := execTarget(proc, unix.AT_FDCWD, "/bin/tool"); err != nil || got != "/bin/tool" {
		t.Errorf("absolute name with cwd outside: %q, %v", got, err)
	}
}

// The same in a real chroot under the filter: relative, absolute, and an
// absolute symlink in the jail all reach the rule on /bin/tool.
func TestExecNotifyChroot(t *testing.T) {
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("no unshare")
	}
	chroot, err := exec.LookPath("chroot")
	if err != nil {
		chroot = "/usr/sbin/chroot"
	}
	if err := exec.CommandContext(t.Context(), unshare, "-r", chroot, "/", "true").Run(); err != nil { //nolint:gosec // fixed tools found in PATH
		t.Skipf("no unprivileged chroot here: %v", err)
	}
	jail := filepath.Join(t.TempDir(), "jail")
	if err := os.MkdirAll(jail+"/bin", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jail+"/bin/tool", []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/tool", jail+"/bin/alias"); err != nil {
		t.Fatal(err)
	}
	script := ""
	for _, name := range []string{"/bin/tool", "bin/tool", "/bin/alias"} {
		script += fmt.Sprintf("%s -r %s %s %s jail-exec; ", unshare, chroot, jail, name)
	}
	cmd, output, listener := startNotifyHelper(t, script)
	var mu sync.Mutex
	var events []runtimepolicy.Request
	stop := serveUntilStopped(t, listener, func(r runtimepolicy.Request) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, r)
		if r.Target == "/bin/tool" {
			return fmt.Errorf("denied tool")
		}
		return nil
	})
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("exec notification hung")
	}
	if err := stop(); err != nil {
		t.Fatalf("serveExec: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) == 1 && events[0].Kind == "proc.exec.invalid" && events[0].Detail == unix.EPERM.Error() && os.Getenv("CI") != "true" {
		t.Skip("this container blocks process_vm_readv; kernel E2E runs in CI")
	}
	var jailed []runtimepolicy.Request
	for _, r := range events {
		if len(r.Argv) == 2 && r.Argv[1] == "jail-exec" {
			jailed = append(jailed, r)
		}
	}
	if len(jailed) != 3 {
		t.Fatalf("want 3 execs in the jail, got %+v; %s", events, output.String())
	}
	for _, r := range jailed {
		if r.Kind != "proc.exec" || r.Target != "/bin/tool" {
			t.Errorf("exec of %q in the jail checked as %s %q", r.Argv[0], r.Kind, r.Target)
		}
	}
	if n := strings.Count(output.String(), "Permission denied"); n != 3 {
		t.Errorf("want 3 denied execs, got %d: %s", n, output.String())
	}
}
