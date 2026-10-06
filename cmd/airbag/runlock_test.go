package main

import (
	"errors"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/session"
)

// A new run takes its session's run lock, waiting out a rollback that
// holds it for a moment, and gives up past that.
func TestLockNewRunWaitsOutABriefHolder(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	other, err := session.Load(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := other.LockRun()
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(100*time.Millisecond, unlock)
	if err := lockNewRun(s); err != nil {
		t.Fatalf("the new run did not wait out a brief holder: %v", err)
	}
	if _, err := other.LockRun(); !errors.Is(err, session.ErrInUse) {
		t.Fatalf("the new run does not hold the lock: %v", err)
	}
}
