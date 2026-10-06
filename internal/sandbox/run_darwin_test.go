//go:build darwin

package sandbox

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

// sandbox-exec execs the agent with the descriptors it was given: the run
// lock passed to the agent stays held after airbag lets go of its own, as
// when airbag is killed, until the agent ends.
func TestTheAgentHoldsTheRunLock(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: t.TempDir(), Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := s.LockRun()
	if err != nil {
		t.Fatal(err)
	}
	agent := exec.CommandContext(t.Context(), "/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/bin/sleep", "30")
	if err := startAgent(s, agent).Start(); err != nil {
		t.Fatal(err)
	}
	unlock()
	if _, err := s.LockRun(); !errors.Is(err, session.ErrInUse) {
		t.Fatalf("the lock was free while the agent ran: %v", err)
	}
	_ = agent.Process.Kill()
	_ = agent.Wait()
	again, err := s.LockRun()
	if err != nil {
		t.Fatalf("the lock was not let go with the agent: %v", err)
	}
	again()
}
