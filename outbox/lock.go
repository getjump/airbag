package outbox

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// LockExecution serializes executors, including crash recovery. The kernel
// releases the lock when the process dies; a second live executor must not
// mistake the first one's running intent for an interrupted operation.
// All handlers must hold this lock until their outcome is recorded.
func (b *Box) LockExecution() (*os.File, error) {
	f, err := os.OpenFile(b.path+".outbox.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another outbox executor is active: %w", err)
	}
	return f, nil // closing the descriptor releases the lock
}
