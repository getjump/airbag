package apply

import (
	"errors"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

func TestQuarantinedExecutorRefusesApplyBeforeSideEffects(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusApplied
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginExecutor(); err != nil {
		t.Fatal(err)
	}
	for _, branch := range []string{"", "work"} {
		if err := Apply(s, nil, nil, Options{Branch: branch}); !errors.Is(err, session.ErrExecutorActive) {
			t.Fatalf("Apply(branch=%q) = %v, want quarantine", branch, err)
		}
	}
	if err := ApplyBranch(s, nil, "work", Options{}); !errors.Is(err, session.ErrExecutorActive) {
		t.Fatalf("ApplyBranch = %v, want quarantine", err)
	}
}
