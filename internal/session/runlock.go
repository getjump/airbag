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

// held keeps the run locks this process took for as long as it runs, by
// the lock's path. The kernel lets go of a lock once no process has it
// open any more, however each ended, so a lock that is free means no run
// of the session is going, whatever its status says.
var held sync.Map

// LockRun takes the session's run lock without waiting. A run holds it
// from before it marks the session running until its process ends;
// rollback holds it while it works, so a run cannot start under it.
// unlock lets it go early; a lock never let go lasts until the process
// ends. Go opens the descriptor with O_CLOEXEC, so a process started
// from here has it only when it is passed on (RunLockFile). It is
// read-only: what it is passed to can write nothing through it.
func (s *Session) LockRun() (unlock func(), err error) {
	f, err := os.OpenFile(s.lockPath(), os.O_CREATE|os.O_RDONLY, 0o600)
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
	held.Store(s.lockPath(), f)
	return func() {
		held.CompareAndDelete(s.lockPath(), f)
		_ = f.Close()
	}, nil
}

// RunLockFile is the run lock this process holds for s, or nil. The macOS
// run passes it to the agent, which nothing ends with airbag there: the
// lock then lasts for as long as the agent, or a process of its that keeps
// the descriptor, runs, past an airbag killed under it too.
func (s *Session) RunLockFile() *os.File {
	if f, ok := held.Load(s.lockPath()); ok {
		return f.(*os.File)
	}
	return nil
}

// lockPath is the run lock's file. Create makes it, so a resume that is
// refused changes nothing in the session; LockRun makes it for a session
// from before the lock.
func (s *Session) lockPath() string { return filepath.Join(s.Dir, "run.lock") }
