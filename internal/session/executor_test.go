package session

import (
	"errors"
	"testing"
)

func TestExecutorLeaseSurvivesLostProcesses(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	s, err := Create(Meta{Workspace: t.TempDir(), Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = StatusStopped
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	stale, err := Load(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BeginExecutor(); err != nil {
		t.Fatal(err)
	}
	if _, err := stale.LockRun(); !errors.Is(err, ErrExecutorActive) {
		t.Fatalf("stale LockRun = %v, want quarantine", err)
	}
	if err := stale.RemoveAll(); !errors.Is(err, ErrExecutorActive) {
		t.Fatalf("stale RemoveAll = %v, want quarantine", err)
	}
	if err := s.EndExecutor(); err != nil {
		t.Fatal(err)
	}
	unlock, err := stale.LockRun()
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}
