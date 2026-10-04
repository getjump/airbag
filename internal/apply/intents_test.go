package apply

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/session"
)

func testBox(t *testing.T) (*session.Session, *outbox.Box) {
	t.Helper()
	ws := t.TempDir()
	box, err := outbox.Open(filepath.Join(t.TempDir(), "effects.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { box.Close() })
	return &session.Session{Meta: session.Meta{ID: "s-test", Workspace: ws}}, box
}

func status(t *testing.T, box *outbox.Box, id string) string {
	t.Helper()
	all, err := box.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range all {
		if it.ID == id {
			return it.Status
		}
	}
	t.Fatalf("no intent %s", id)
	return ""
}

// An intent recorded as running when airbag stopped is reported as
// unknown and never run again.
func TestRunningBecomesUnknown(t *testing.T) {
	s, box := testBox(t)
	it, err := box.Push(outbox.Intent{Kind: "git.push", Argv: []string{"git", "push", "origin", "main"}, Cwd: s.Workspace})
	if err != nil {
		t.Fatal(err)
	}
	it.Status = outbox.Running
	if err := box.Update(it); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runIntents(s, box, false, nil, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if got := status(t, box, it.ID); got != outbox.Unknown {
		t.Fatalf("status %s, want unknown; output: %s", got, out.String())
	}
	out.Reset()
	if err := runIntents(s, box, false, nil, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if got := status(t, box, it.ID); got != outbox.Unknown || out.Len() != 0 {
		t.Fatalf("second run touched it: %s %q", got, out.String())
	}
}

// After a session put git config or hooks into the repository, its
// pushes wait for --trust-git, with or without --yes.
func TestRiskyWaitsForTrust(t *testing.T) {
	s, box := testBox(t)
	it, err := box.Push(outbox.Intent{Kind: "git.push", Argv: []string{"git", "push", "origin", "main"}, Cwd: s.Workspace})
	if err != nil {
		t.Fatal(err)
	}
	for _, yes := range []bool{true, false} {
		var out bytes.Buffer
		if err := runIntents(s, box, true, nil, Options{Yes: yes, Out: &out}); err != nil {
			t.Fatal(err)
		}
		if got := status(t, box, it.ID); got != outbox.Pending || !strings.Contains(out.String(), "--trust-git") {
			t.Fatalf("yes=%v: status %s, output %q", yes, got, out.String())
		}
	}
}
