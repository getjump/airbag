//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

// Only a branched $HOME passes paths through, so only there does run
// make them. One that is not branched may be one the session could not
// record (HOME=/nonexistent with --no-home): nothing is made in it.
func TestPrepareHomeOnlyInABranchedHome(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := t.TempDir()
	missing := filepath.Join(t.TempDir(), "home")
	meta := session.Meta{Workspace: ws, Home: missing,
		Passthrough: []string{".codex/sessions/"}, BranchHoles: []string{".claude/projects/-x/memory"}}
	s, err := session.Create(meta)
	if err != nil {
		t.Fatal(err)
	}
	if !s.HomeUnrecorded() {
		t.Fatalf("a missing $HOME is recorded: %+v", s.HomeID)
	}
	if err := prepareHome(s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("run made the $HOME it could not record: %v", err)
	}

	meta.Home, meta.OverHome = t.TempDir(), true
	if s, err = session.Create(meta); err != nil {
		t.Fatal(err)
	}
	if err := prepareHome(s); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{".codex/sessions", ".claude/projects/-x/memory"} {
		if st, err := os.Stat(filepath.Join(meta.Home, p)); err != nil || !st.IsDir() {
			t.Errorf("a branched $HOME lacks ~/%s: %v", p, err)
		}
	}
}
