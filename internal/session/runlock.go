package session

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// ErrInUse: another process holds the session's run lock, a run or a
// rollback of it.
var ErrInUse = errors.New("in use by another airbag process")

// ErrAgentLives: a process of an earlier run still holds the session's
// agent lock. On macOS nothing ends the agent with airbag, so the agent,
// or a process it left running, can outlive the run.
var ErrAgentLives = errors.New("a process of its last run is still running")

// held keeps the run locks this process took for as long as it runs. The
// kernel lets go of a lock when its process ends, however it ends, so a
// lock that is free means no run of the session is going, whatever its
// status says.
var held sync.Map

// LockRun takes the session's run lock without waiting. A run holds it
// from before it marks the session running until its process ends;
// rollback holds it while it works, so a run cannot start under it.
// unlock lets it go early; a lock never let go lasts until the process
// ends. The descriptor stays airbag's: Go opens it with O_CLOEXEC, and
// nothing passes it on. The agent lock is checked too: held, it is
// ErrAgentLives.
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
	// With the run lock held, no run starts to take the agent lock; one
	// held now is an earlier run's.
	if err := s.probeAgent(); err != nil {
		_ = f.Close()
		return nil, err
	}
	held.Store(f, struct{}{})
	return func() {
		held.Delete(f)
		_ = f.Close()
	}, nil
}

// LockAgent takes the session's agent lock for a run to pass to its
// agent, which holds it from then on: on macOS the lock lasts as long as
// the agent, or a process of its that keeps the descriptor, runs, past an
// airbag killed under it too, and LockRun refuses until then. The
// descriptor is read-only, so the agent can write nothing through it, and
// its lock is a shared one: on NFS, where flock is a byte-range lock, an
// exclusive one would need a writable descriptor. The caller closes its
// own once the agent has started.
func (s *Session) LockAgent() (*os.File, error) {
	if err := s.probeAgent(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.AgentLockPath(), os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// probeAgent is ErrAgentLives while anything holds the agent lock: an
// exclusive lock, through a writable descriptor of airbag's own, cannot
// be taken beside a shared one.
func (s *Session) probeAgent() error {
	f, err := os.OpenFile(s.AgentLockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return ErrAgentLives
		}
		return err
	}
	return nil
}

// lockPath is the run lock's file. Create makes it, so a resume that is
// refused changes nothing in the session; LockRun makes it for a session
// from before the lock.
func (s *Session) lockPath() string { return filepath.Join(s.Dir, "run.lock") }

// AgentLockPath is the agent lock's file, made with the run lock's: `lsof`
// on it finds what still holds it.
func (s *Session) AgentLockPath() string { return filepath.Join(s.Dir, "agent.lock") }
