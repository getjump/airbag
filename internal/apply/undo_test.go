package apply

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/review"
	"github.com/getjump/airbag/internal/session"
)

// undoSession lays out a workspace and its upper layer as overlayfs
// would leave them: mod.txt changed, new.txt added, del.txt deleted.
func undoSession(t *testing.T) (*session.Session, *outbox.Box) {
	t.Helper()
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := filepath.Join(t.TempDir(), "ws")
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	put := func(p, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put(filepath.Join(ws, "mod.txt"), "user\n")
	put(filepath.Join(ws, "del.txt"), "keep me\n")
	put(filepath.Join(s.WSUpper(), "mod.txt"), "agent\n")
	put(filepath.Join(s.WSUpper(), "sub", "new.txt"), "new\n")
	if err := unix.Mknod(filepath.Join(s.WSUpper(), "del.txt"), syscall.S_IFCHR, 0); err != nil {
		t.Skipf("cannot create a whiteout here: %v", err)
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { box.Close() })
	return s, box
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}

func scan(t *testing.T, s *session.Session) map[string]string {
	t.Helper()
	cs, err := review.Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, c := range cs {
		m[c.Rel] = c.Kind
	}
	return m
}

func TestApplyRollback(t *testing.T) {
	s, box := undoSession(t)
	ws := s.Workspace
	before := scan(t, s)
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Force: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if read(t, filepath.Join(ws, "mod.txt")) != "agent\n" || read(t, filepath.Join(ws, "sub", "new.txt")) != "new\n" {
		t.Fatal("not applied")
	}
	if _, err := os.Stat(filepath.Join(ws, "del.txt")); err == nil {
		t.Fatal("del.txt not deleted")
	}
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if read(t, filepath.Join(ws, "mod.txt")) != "user\n" || read(t, filepath.Join(ws, "del.txt")) != "keep me\n" {
		t.Fatalf("not restored: mod=%q del=%q", read(t, filepath.Join(ws, "mod.txt")), read(t, filepath.Join(ws, "del.txt")))
	}
	if _, err := os.Stat(filepath.Join(ws, "sub")); err == nil {
		es, _ := os.ReadDir(filepath.Join(ws, "sub"))
		g, _ := listGenerations(s)
		t.Fatalf("sub/ left behind: %v %v", es, g)
	}
	if after := scan(t, s); len(after) != len(before) || after["mod.txt"] != review.Modified || after["del.txt"] != review.Deleted {
		t.Fatalf("changes not back in the session: before %v after %v", before, after)
	}
	// And it applies again.
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Force: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if read(t, filepath.Join(ws, "mod.txt")) != "agent\n" {
		t.Fatal("second apply")
	}
}

// A step that fails undoes the steps before it.
func TestApplyIsAllOrNothing(t *testing.T) {
	s, box := undoSession(t)
	ws := s.Workspace
	// sub/ cannot be created: a file is in the way.
	if err := os.WriteFile(filepath.Join(ws, "sub"), []byte("in the way\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := Apply(s, mustScan(t, s), box, Options{Yes: true, Force: true, Out: &out})
	if err == nil || !strings.Contains(err.Error(), "nothing applied") {
		t.Fatalf("err = %v", err)
	}
	if read(t, filepath.Join(ws, "mod.txt")) != "user\n" || read(t, filepath.Join(ws, "del.txt")) != "keep me\n" {
		t.Fatal("a failed apply left changes behind")
	}
	if interrupted(s) != nil {
		t.Fatal("rolled-back generation still marked as interrupted")
	}
}

// A file changed after the apply is left as it is.
func TestRollbackKeepsLaterEdits(t *testing.T) {
	s, box := undoSession(t)
	ws := s.Workspace
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Force: true, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "mod.txt"), []byte("edited after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Rollback(s, []string{"intent i-1 `git push` (done)"}, &out); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(ws, "mod.txt")) != "edited after\n" {
		t.Fatal("rollback overwrote a later edit")
	}
	if read(t, filepath.Join(ws, "del.txt")) != "keep me\n" {
		t.Fatal("the rest was not rolled back")
	}
	for _, want := range []string{"left as is", "not undone: intent i-1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q: %s", want, out.String())
		}
	}
}

func mustScan(t *testing.T, s *session.Session) []review.Change {
	t.Helper()
	cs, err := review.Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// A clone branch (macOS): review compares the clone with the real
// tree, apply copies from it and leaves it alone, rollback restores.
func TestCloneApplyRollback(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := filepath.Join(t.TempDir(), "ws")
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	for root, files := range map[string]map[string]string{
		ws:           {"mod.txt": "user\n", "del.txt": "keep me\n", "same.txt": "same\n"},
		s.CloneDir(): {"mod.txt": "agent\n", "new.txt": "new\n", "same.txt": "same\n"},
	} {
		for name, data := range files {
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer box.Close()
	got := scan(t, s)
	if len(got) != 3 || got["mod.txt"] != review.Modified || got["new.txt"] != review.Added || got["del.txt"] != review.Deleted {
		t.Fatalf("scan %v", got)
	}
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Force: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if read(t, filepath.Join(ws, "mod.txt")) != "agent\n" || read(t, filepath.Join(s.CloneDir(), "mod.txt")) != "agent\n" {
		t.Fatal("apply did not copy from the clone, or emptied it")
	}
	if left := scan(t, s); len(left) != 0 {
		t.Fatalf("after apply the clone still differs: %v", left)
	}
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if read(t, filepath.Join(ws, "mod.txt")) != "user\n" || read(t, filepath.Join(ws, "del.txt")) != "keep me\n" {
		t.Fatal("not restored")
	}
	if _, err := os.Stat(filepath.Join(s.CloneDir(), "del.txt")); err == nil {
		t.Fatal("rollback put a deleted file into the clone")
	}
	if back := scan(t, s); len(back) != 3 {
		t.Fatalf("changes not back after rollback: %v", back)
	}
}
