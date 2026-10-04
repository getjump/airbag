package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/apply"
	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/review"
	"github.com/getjump/airbag/internal/session"
)

// After a rollback that left a path, the session holds the user's
// version of it from before the apply; discard must not delete it.
func TestDiscardKeepsVersionsARollbackLeft(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := filepath.Join(t.TempDir(), "ws")
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	mod := filepath.Join(ws, "mod.txt")
	for p, data := range map[string]string{mod: "user\n", filepath.Join(s.CloneDir(), "mod.txt"): "agent\n"} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	cs, err := review.Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := apply.Apply(s, cs, box, apply.Options{Yes: true, Force: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	_ = box.Close()
	if err := os.WriteFile(mod, []byte("edited after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := apply.Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	saved := filepath.Join(s.Dir, "undo", "1", "saved", "0")
	if b, err := os.ReadFile(saved); err != nil || string(b) != "user\n" {
		t.Fatalf("setup: the rollback did not keep the user's version at %s: %q %v\n%s", saved, b, err, out.String())
	}

	err = cmdDiscard([]string{s.ID, "--yes"})
	if err == nil {
		t.Fatalf("discard deleted the user's version of %s from before the apply", mod)
	}
	for _, want := range []string{"airbag rollback " + s.ID, saved} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("discard's refusal lacks %q: %v", want, err)
		}
	}
	if b, err := os.ReadFile(saved); err != nil || string(b) != "user\n" {
		t.Fatalf("the user's version is gone after the refused discard: %q %v", b, err)
	}

	if err := cmdDiscard([]string{s.ID, "--yes", "--force"}); err != nil {
		t.Fatalf("discard --force: %v", err)
	}
	if _, err := os.Lstat(s.Dir); err == nil {
		t.Fatal("discard --force left the session")
	}
}
