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
