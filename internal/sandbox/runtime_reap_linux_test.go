package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The microVM's guest reads the tree for its export only once no process
// of the agent's is left: one SIGKILL has reached may still be writing.
// reapAll waits for every process, orphans included (they come to PID 1),
// and fails when one does not go within its limit. It runs in a helper
// process, a child subreaper as PID 1 is, since it waits for any child.
func TestReapAllWaitsForEveryProcess(t *testing.T) {
	for _, mode := range []string{"reaps", "stuck"} {
		t.Run(mode, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "written")
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestReapAllHelper$") //nolint:gosec // this test binary, as the helper
			cmd.Env = append(os.Environ(), "AIRBAG_TEST_REAP="+mode, "AIRBAG_TEST_REAP_FILE="+out)
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Run(); err != nil || !strings.Contains(output.String(), "REAP OK") {
				t.Fatalf("%v\n%s", err, output.String())
			}
		})
	}
}

func TestReapAllHelper(t *testing.T) {
	mode, file := os.Getenv("AIRBAG_TEST_REAP"), os.Getenv("AIRBAG_TEST_REAP_FILE")
	if mode == "" {
		return
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	// A child whose own child keeps writing in the background, left
	// behind as an orphan once the child exits, as an agent's may be.
	writer := exec.CommandContext(t.Context(), "/bin/sh", "-c", `(while :; do echo x >> "$0"; done) & exit 0`, file) //nolint:gosec // fixed test command
	writer.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := writer.Run(); err != nil {
		t.Fatal(err)
	}
	pgid := writer.Process.Pid
	for deadline := time.Now().Add(5 * time.Second); size(file) == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the background writer never wrote")
		}
	}
	killGroup := func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) }
	switch mode {
	case "reaps":
		if err := reapAll(killGroup, 5*time.Second); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Kill(-pgid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Fatalf("a process of the group is left: %v", err)
		}
		before := size(file)
		time.Sleep(100 * time.Millisecond)
		if after := size(file); after != before {
			t.Fatalf("the tree still changes after reapAll: %d then %d bytes", before, after)
		}
	case "stuck":
		// A process the signal does not stop holds the export back
		// only as long as the limit, then fails it.
		start := time.Now()
		err := reapAll(func() {}, 200*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "did not stop") || time.Since(start) > 3*time.Second {
			t.Fatalf("reapAll with a process left: %v after %s", err, time.Since(start))
		}
		if err := reapAll(killGroup, 5*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Println("REAP OK")
}

func size(p string) int64 {
	fi, err := os.Stat(p) //nolint:gosec // a file this test made
	if err != nil {
		return 0
	}
	return fi.Size()
}
