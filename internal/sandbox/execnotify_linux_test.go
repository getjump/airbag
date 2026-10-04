//go:build linux

package sandbox

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
			if got := runBPF(t, p, seccompData(abi.arch, nr, 0)); got != unix.SECCOMP_RET_USER_NOTIF {
				t.Fatalf("exec passed: %#x", got)
			}
		}
		if got := runBPF(t, p, seccompData(abi.arch, 1, 0)); got != unix.SECCOMP_RET_ALLOW {
			t.Fatal("non-exec blocked")
		}
		for _, d := range [][]byte{seccompData(unix.AUDIT_ARCH_I386, 11, 0), seccompData(abi.arch, x32Bit|abi.execve, 0)} {
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

// This exercises real kernel notifications and tracee memory, without needing
// user namespaces or /dev/fuse. The sandbox E2E adds those layers in CI.
func TestExecNotifyKernel(t *testing.T) {
	if execArch() == 0 {
		t.Skip("unsupported architecture")
	}
	host, child, err := socketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	defer child.Close()
	sentinel := filepath.Join(t.TempDir(), "should-not-exist")
	cmd := exec.Command(os.Args[0], "-test.run=^TestExecNotifyHelper$")
	cmd.Env = append(os.Environ(), "AIRBAG_TEST_NOTIFY_HELPER=1", "AIRBAG_TEST_NOTIFY_COMMAND=exec /usr/bin/touch "+sentinel)
	cmd.ExtraFiles = []*os.File{child}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child.Close()
	listener, err := receiveListener(host)
	if err != nil {
		_ = cmd.Wait()
		t.Fatalf("listener: %v: %s", err, output.String())
	}
	defer unix.Close(listener)
	var mu sync.Mutex
	var events []runtimepolicy.Request
	go func() {
		_ = serveExec(listener, func(r runtimepolicy.Request) error {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, r)
			if filepath.Base(r.Target) == "touch" {
				return fmt.Errorf("denied touch")
			}
			return nil
		})
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatal("exec notification hung")
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
