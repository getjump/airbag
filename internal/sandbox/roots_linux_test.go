package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

// An optional runtime's session on a replaced workspace is stopped, not
// left running: resume, review and discard must still reach it. It gets
// no copy of the directory now at the path.
func TestOptionalRunStopsOnReplacedRoots(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	parent := t.TempDir()
	ws := filepath.Join(parent, "ws")
	if err := os.Mkdir(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Backend: "gvisor", Clone: true,
		Runtime: session.RuntimeConfig{RootFS: t.TempDir(), Binary: "/bin/false"}})
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
	saved, err := session.Load(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Status != session.StatusStopped || saved.RuntimeCopied {
		t.Fatalf("after the refusal: status %s, copied %t", saved.Status, saved.RuntimeCopied)
	}
	if _, err := os.Lstat(s.CloneDir()); !os.IsNotExist(err) {
		t.Fatalf("made a copy of the replaced workspace: %v", err)
	}
}
