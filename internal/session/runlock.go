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
