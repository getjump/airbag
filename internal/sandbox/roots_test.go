package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

// A root that became another directory after the session was created
// or resumed stops the run before anything is made for it.
func TestRunChecksTheRootsFirst(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	parent := t.TempDir()
	ws := filepath.Join(parent, "ws")
	home := t.TempDir()
	if err := os.Mkdir(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, OverHome: true, Clone: true,
		Passthrough: []string{".codex/sessions/"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(ws, filepath.Join(parent, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	code, err := Run(s, nil, nil)
	if code == 0 || err == nil || !strings.Contains(err.Error(), "was not started") {
		t.Fatalf("a replaced workspace runs: code=%d err=%v", code, err)
	}
	for _, p := range []string{filepath.Join(home, ".codex"), s.CloneDir()} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("made %s for a run on a replaced workspace: %v", p, err)
		}
	}
}
