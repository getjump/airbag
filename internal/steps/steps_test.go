package steps

import (
	"encoding/json"
	"fmt"
	"io/fs"
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

// A name that is not UTF-8 is still a name on Linux: the changes under
// such a directory are the step's like any others.
func TestStepsSeeNamesThatAreNotUTF8(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Backend: "gvisor", Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTracker(s)
	dir := filepath.Join(s.CloneDir(), "bad\xff")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Skipf("this filesystem takes no such name: %v", err) // APFS
	}
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("agent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := tr.Record("Bash", "edit", "call-1")
	want := []string{"+ws:bad\xff/f"}
	if !slices.Equal(st.Changes, want) {
		t.Fatalf("step changes %q, want %q", st.Changes, want)
	}
	// As recorded, not as JSON would spell it.
	sts, err := Read(s)
	if err != nil || len(sts) != 1 || !slices.Equal(sts[0].Changes, want) {
		t.Fatalf("read back: %+v, %v", sts, err)
	}
}

// Only a change that is not UTF-8 keeps its bytes beside it: a step of
// many ordinary changes and one such stays about the size it was.
func TestStoredKeepsOnlyTheBytesJSONWouldLose(t *testing.T) {
	st := Step{Changes: []string{"+ws:a", "~ws:bad\xff", "-ws:c"}}
	r := stored(st)
	if len(r.Raw) != 1 || string(r.Raw[1]) != "~ws:bad\xff" {
		t.Fatalf("raw bytes kept: %v", r.Raw)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back record
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Raw) != 1 || string(back.Raw[1]) != "~ws:bad\xff" {
		t.Fatalf("raw bytes read back: %v", back.Raw)
	}
	if r := stored(Step{Changes: []string{"+ws:a"}}); r.Raw != nil {
		t.Fatalf("raw bytes kept for a step of UTF-8 names: %v", r.Raw)
	}
}

// Directories count toward the cap: a tree of empty ones is not walked
// past it.
func TestWalkCountsDirectories(t *testing.T) {
	old := maxEntries
	maxEntries = 10
	t.Cleanup(func() { maxEntries = old })
	root := t.TempDir()
	for i := range 50 {
		if err := os.MkdirAll(filepath.Join(root, fmt.Sprintf("d%02d", i), "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	n := 0
	walk(r, func(string, fs.FileInfo) { n++ })
	if n != maxEntries {
		t.Fatalf("walked %d entries, want the cap of %d", n, maxEntries)
	}
}
