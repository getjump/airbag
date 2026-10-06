package steps

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

// An optional runtime's branch is a clone of the whole workspace, not an
// upper layer: a tool call's changes there are its step's, and a file
// gone from the clone is a deletion.
func TestStepsInAClone(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Backend: "gvisor", Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	clone := s.CloneDir()
	write := func(rel, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(clone, rel)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(clone, rel), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("seed.txt", "original\n")
	write("dir/removed.txt", "original\n")
	tr := NewTracker(s)

	write("seed.txt", "changed by the agent\n")
	if err := os.Remove(filepath.Join(clone, "dir/removed.txt")); err != nil {
		t.Fatal(err)
	}
	write("new.txt", "made by the agent\n")
	st := tr.Record("Bash", "edit", "call-1")
	want := []string{"+ws:new.txt", "-ws:dir/removed.txt", "~ws:seed.txt"}
	if !slices.Equal(st.Changes, want) {
		t.Fatalf("step changes %q, want %q", st.Changes, want)
	}
	if st := tr.Record("Bash", "noop", "call-2"); len(st.Changes) != 0 {
		t.Fatalf("a call that changed nothing: %q", st.Changes)
	}
}
