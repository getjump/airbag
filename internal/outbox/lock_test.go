package outbox

import (
	"path/filepath"
	"testing"
)

func TestLiveExecutorCannotBeRecoveredAsCrashed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "effects.db")
	a, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	lock, err := a.LockExecution()
	if err != nil {
		t.Fatal(err)
	}
	if other, err := b.LockExecution(); err == nil {
		_ = other.Close()
		t.Fatal("second executor acquired a live lock")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := b.LockExecution()
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
}
