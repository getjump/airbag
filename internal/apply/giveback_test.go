package apply

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/outbox"
)

// The agent may make any path of its branch a link once an apply took its
// version out, during a run resumed after a partial apply, say. Giving that
// version back must write it into the branch or nowhere: through a link to
// a host directory it would put a file the user never reviewed there.
func TestRollbackWritesNothingThroughALinkInTheBranch(t *testing.T) {
	for _, clone := range []bool{false, true} {
		t.Run(map[bool]string{false: "upper", true: "clone"}[clone], func(t *testing.T) {
			t.Setenv("AIRBAG_HOME", t.TempDir())
			ws := filepath.Join(t.TempDir(), "ws")
			if err := os.MkdirAll(filepath.Join(ws, "a"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(ws, "a", "b.txt"), []byte("user\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Clone: clone})
			if err != nil {
				t.Fatal(err)
			}
			s.Status = session.StatusStopped
			branch := s.WSBranch()
			if clone {
				// A clone holds the whole workspace.
				if err := os.MkdirAll(filepath.Join(branch, "a"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for rel, body := range map[string]string{"a/b.txt": "agent\n", "other.txt": "kept in the session\n"} {
				p := filepath.Join(branch, rel)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			box, err := outbox.Open(s.EffectsPath())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = box.Close() }()
			var out bytes.Buffer
			if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Only: []string{"a"}, Out: &out}); err != nil {
				t.Fatal(err, out.String())
			}
			if got := read(t, filepath.Join(ws, "a", "b.txt")); got != "agent\n" {
				t.Fatalf("not applied: %q", got)
			}
			outside := t.TempDir()
			if err := os.RemoveAll(filepath.Join(branch, "a")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(branch, "a")); err != nil {
				t.Fatal(err)
			}
			out.Reset()
			err = Rollback(s, nil, &out)
			if b, readErr := os.ReadFile(filepath.Join(outside, "b.txt")); readErr == nil {
				t.Fatalf("rollback wrote %q through the branch's link, outside the session", b)
			}
			if err == nil {
				t.Fatalf("rollback through a link in the branch reported success: %s", out.String())
			}
			// The user's version from before the apply is still kept.
			if !strings.Contains(err.Error(), "return the agent's version") {
				t.Fatalf("rollback: %v", err)
			}
			held, herr := HeldVersions(s)
			if herr != nil || len(held) != 1 {
				t.Fatalf("held versions %v %v", held, herr)
			}
			if got := read(t, held[0].Saved); got != "user\n" {
				t.Fatalf("the kept version is %q", got)
			}
		})
	}
}

// A rollback runs on a stopped session: during a run, the agent could
// change the branch under it.
func TestRollbackRefusesARunningSession(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := t.TempDir()
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.WSUpper(), "f"), []byte("agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	s.Status = session.StatusRunning
	if err := Rollback(s, nil, &out); err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatalf("rolled back a running session: %v", err)
	}
	if got := read(t, filepath.Join(ws, "f")); got != "agent\n" {
		t.Fatalf("the refused rollback changed the file: %q", got)
	}
}
