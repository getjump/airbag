package session

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A resumed run holds the session's run lock from before it marks the
// session running: a rollback started in the time before the run's host
// services answer finds it taken. A resume refused lets it go.
func TestResumeHoldsTheRunLock(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := t.TempDir()
	s, err := Create(Meta{Workspace: ws, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = StatusStopped
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := ResumeChecked(s.ID, ws, func(*Session) error { return errors.New("refused") }); err == nil {
		t.Fatal("the validation did not refuse")
	}
	unlock, err := s.LockRun()
	if err != nil {
		t.Fatalf("a refused resume kept the lock: %v", err)
	}
	unlock()
	if _, err := Resume(s.ID, ws); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LockRun(); !errors.Is(err, ErrInUse) {
		t.Fatalf("the run lock was not held by the resumed run: %v", err)
	}
}

// The kernel lets go of the lock when its process ends, however it ends:
// a run that was killed leaves no lock behind for its running mark.
func TestRunLockGoesWithItsProcess(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	s, err := Create(Meta{Workspace: t.TempDir(), Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRunLockHelper$") //nolint:gosec // this test binary, as the holder
	cmd.Env = append(os.Environ(), "AIRBAG_TEST_LOCK_DIR="+s.Dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if n, _ := out.Read(buf); !strings.Contains(string(buf[:n]), "LOCKED") {
		t.Fatalf("the helper did not take the lock: %q", buf[:n])
	}
	if _, err := s.LockRun(); !errors.Is(err, ErrInUse) {
		t.Fatalf("the lock another process holds was free: %v", err)
	}
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait()
	unlock, err := s.LockRun()
	if err != nil {
		t.Fatalf("the lock of a killed process was not let go: %v", err)
	}
	unlock()
}

func TestRunLockHelper(t *testing.T) {
	dir := os.Getenv("AIRBAG_TEST_LOCK_DIR")
	if dir == "" {
		return
	}
	if _, err := (&Session{Dir: dir}).LockRun(); err != nil {
		t.Fatal(err)
	}
	_, _ = os.Stdout.WriteString("LOCKED\n")
	time.Sleep(time.Minute)
}

// The agent lock that a run passes to its agent is held by the agent: the
// run lock cannot be taken while the agent, or a process of its that
// keeps the descriptor, runs (on macOS past an airbag killed under it),
// and the run lock itself is never in the agent's hands.
func TestAgentLockHoldsOffTheRunLock(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	s, err := Create(Meta{Workspace: t.TempDir(), Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	lock, err := s.LockAgent()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock.Write([]byte("x")); err == nil {
		t.Fatal("the agent lock's descriptor writes")
	}
	child := exec.CommandContext(t.Context(), "sleep", "30")
	child.ExtraFiles = []*os.File{lock}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	_ = lock.Close()
	if _, err := s.LockRun(); !errors.Is(err, ErrAgentLives) {
		t.Fatalf("the run lock with the agent lock held: %v", err)
	}
	if _, err := s.LockAgent(); !errors.Is(err, ErrAgentLives) {
		t.Fatalf("a second agent lock: %v", err)
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	unlock, err := s.LockRun()
	if err != nil {
		t.Fatalf("the run lock once the agent is gone: %v", err)
	}
	unlock()
}
