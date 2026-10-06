package session

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// ErrInUse: another process holds the session's run lock, a run or a
// rollback of it.
var ErrInUse = errors.New("in use by another airbag process")

// held keeps the run locks this process took for as long as it runs. The
// kernel lets go of a lock when its process ends, however it ends, so a
// lock that is free means no run of the session is going, whatever its
// status says.
var held sync.Map

// LockRun takes the session's run lock without waiting. A run holds it
// from before it marks the session running until its process ends;
// rollback holds it while it works, so a run cannot start under it.
// unlock lets it go early; a lock never let go lasts until the process
// ends. The descriptor is not passed on to the agent: Go opens it with
// O_CLOEXEC.
func (s *Session) LockRun() (unlock func(), err error) {
	f, err := os.OpenFile(s.lockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrInUse
		}
		return nil, err
	}
	held.Store(f, struct{}{})
	return func() {
		held.Delete(f)
		_ = f.Close()
	}, nil
}

// lockPath is the run lock's file. Create makes it, so a resume that is
// refused changes nothing in the session; LockRun makes it for a session
// from before the lock.
func (s *Session) lockPath() string { return filepath.Join(s.Dir, "run.lock") }

// agentPath is where a run that has no parent-death signal for its agent
// (macOS) writes the agent's process ID while it runs.
func (s *Session) agentPath() string { return filepath.Join(s.RunDir(), "agent.pid") }

// NoteAgent records pid as the running agent's, for AgentAlive after the
// airbag process that started it is gone: on macOS the agent outlives a
// SIGKILL of airbag, and so does nothing else of the run. forget removes
// the record once the agent has exited.
func (s *Session) NoteAgent(pid int) (forget func(), err error) {
	if err := os.WriteFile(s.agentPath(), []byte(strconv.Itoa(pid)), 0o600); err != nil {
		return nil, err
	}
	return func() { _ = os.Remove(s.agentPath()) }, nil
}

// AgentAlive reports a recorded agent that is still running. A process ID
// used again by another process reads as alive: that only holds a rollback
// or a resume back, which can be run again once it has gone.
func (s *Session) AgentAlive() (pid int, alive bool) {
	b, err := os.ReadFile(s.agentPath())
	if err != nil {
		return 0, false
	}
	pid, err = strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return 0, false
	}
	err = syscall.Kill(pid, 0)
	return pid, err == nil || errors.Is(err, syscall.EPERM)
}
