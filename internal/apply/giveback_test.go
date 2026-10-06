package apply

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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
			if left, _ := os.ReadDir(outside); len(left) != 0 {
				t.Fatalf("rollback wrote %v through the branch's link, outside the session", left)
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
			// With the link gone, the rollback finishes.
			if err := os.Remove(filepath.Join(branch, "a")); err != nil {
				t.Fatal(err)
			}
			out.Reset()
			if err := Rollback(s, nil, &out); err != nil {
				t.Fatalf("the rollback once the link is gone: %v\n%s", err, out.String())
			}
			if got := read(t, filepath.Join(ws, "a", "b.txt")); got != "user\n" {
				t.Fatalf("not rolled back: %q", got)
			}
			if got := read(t, filepath.Join(branch, "a", "b.txt")); got != "agent\n" {
				t.Fatalf("the agent's version is not back in the session: %q", got)
			}
		})
	}
}

// On macOS the agent may write the clone's own entry in the session. A
// link put there must not lead the rollback elsewhere: os.OpenRoot
// follows links in the name it opens.
func TestRollbackRefusesABranchThatIsALink(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(filepath.Join(ws, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "a", "b.txt"), []byte("user\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	clone := s.CloneDir()
	for rel, body := range map[string]string{"a/b.txt": "agent\n", "other.txt": "kept in the session\n"} {
		p := filepath.Join(clone, rel)
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
	// The apply took a/b.txt out of the clone; the clone itself moves
	// away, and a link to an outside directory takes its place.
	outside := t.TempDir()
	if err := os.Rename(clone, clone+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, clone); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	err = Rollback(s, nil, &out)
	if left, _ := os.ReadDir(outside); len(left) != 0 {
		t.Fatalf("rollback wrote %v through the link at the clone's place", left)
	}
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("rollback through a branch that is a link: %v\n%s", err, out.String())
	}
}

// What the agent left at a replaced directory's path that is not a
// directory gets no opaque mark and holds nothing up: a FIFO opened to
// mark it would block the rollback until someone wrote to it.
func TestMarkOpaqueLeavesWhatIsNotADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	done := make(chan error, 2)
	go func() {
		done <- markOpaqueIn(r, "fifo")
		done <- markOpaqueIn(r, "file")
	}()
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("marking a FIFO blocked")
		}
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	if err := markOpaqueIn(r, "out/x"); err == nil {
		t.Fatal("a path that leads out of the branch was not refused")
	}
}

// A version the agent put at the path after giveBack found it empty (in
// a run still going) stays: the agent's version from the journal is not
// renamed over it, and no temp file is left beside it.
func TestGiveBackKeepsWhatAppearedSince(t *testing.T) {
	branch, src := t.TempDir(), filepath.Join(t.TempDir(), "journal-version")
	if err := os.WriteFile(src, []byte("from the journal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(branch, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(branch, "d", "f"), []byte("newer, the agent's\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", filepath.Join(branch, "d", "l")); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(branch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := copyFileIn(r, src, "d/f", 0o644); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(branch, "d", "f")); got != "newer, the agent's\n" {
		t.Fatalf("the agent's newer version was replaced: %q", got)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink("from the journal", link); err != nil {
		t.Fatal(err)
	}
	if err := copyTreeIn(r, link, "d/l"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.Readlink(filepath.Join(branch, "d", "l")); got != "elsewhere" {
		t.Fatalf("the agent's link was replaced: %q", got)
	}
	if ents, _ := os.ReadDir(filepath.Join(branch, "d")); len(ents) != 2 {
		t.Fatalf("left beside them: %v", ents)
	}
}
