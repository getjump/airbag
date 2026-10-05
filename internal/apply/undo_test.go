package apply

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/review"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/outbox"
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
	t.Cleanup(func() { _ = box.Close() })
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

// A failed step says what the rollback left, without a "<nil>" for a
// rollback that left paths but returned no error.
func TestApplyFailedMessage(t *testing.T) {
	step, busy := errors.New("disk full"), errors.New("busy")
	for _, c := range []struct {
		left int
		rerr error
		want string
	}{
		{0, nil, "nothing applied"},
		{2, nil, "left 2 paths as they are"},
		{1, busy, "also failed (busy)"},
	} {
		err := applyFailed("a.txt", "s1", step, c.left, c.rerr)
		if msg := err.Error(); !strings.Contains(msg, c.want) || strings.Contains(msg, "nil") {
			t.Errorf("left=%d rerr=%v: %q", c.left, c.rerr, msg)
		}
		if !errors.Is(err, step) || (c.rerr != nil && !errors.Is(err, c.rerr)) {
			t.Errorf("left=%d rerr=%v: %v does not wrap its causes", c.left, c.rerr, err)
		}
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
	defer func() { _ = box.Close() }()
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

// appliedReplacedDir lays out a clone session in which the agent
// replaced the user's file d with a directory holding the file inner
// (a path inside d), and applies it. It returns the real path of d.
func appliedReplacedDir(t *testing.T, inner string) (*session.Session, string) {
	t.Helper()
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := filepath.Join(t.TempDir(), "ws")
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	for p, data := range map[string]string{
		filepath.Join(ws, "d"):                  "user file\n",
		filepath.Join(s.CloneDir(), "d", inner): "agent\n",
	} {
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
	t.Cleanup(func() { _ = box.Close() })
	if got := scan(t, s); got["d"] != review.Replaced || got[filepath.Join("d", inner)] != review.Added {
		t.Fatalf("scan %v", got)
	}
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Force: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	d := filepath.Join(ws, "d")
	if read(t, filepath.Join(d, inner)) != "agent\n" {
		t.Fatal("replaced directory not applied")
	}
	return s, d
}

// keptVersion returns the version from before the apply that the last
// generation of s still holds for path, or fails.
func keptVersion(t *testing.T, s *session.Session, path string) (*generation, string) {
	t.Helper()
	gs, err := listGenerations(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) == 0 {
		t.Fatalf("no generation left: the version of %s from before the apply is gone", path)
	}
	g, err := loadGeneration(gs[len(gs)-1].dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range g.Entries {
		if e.Path == path {
			if e.Saved == "" {
				t.Fatalf("%s: entry kept without its previous version", path)
			}
			return g, read(t, e.Saved)
		}
	}
	t.Fatalf("generation %s does not keep %s: %+v", g.dir, path, g.Entries)
	return nil, ""
}

// A file the user adds inside a replaced directory after the apply
// survives the rollback; the directory stays whole, the agent's file in
// it included, with the user's file from before the apply kept.
func TestRollbackKeepsFileAddedToReplacedDir(t *testing.T) {
	s, d := appliedReplacedDir(t, "inner.txt")
	added := filepath.Join(d, "user.txt")
	if err := os.WriteFile(added, []byte("added after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if got := read(t, added); got != "added after\n" {
		t.Fatalf("rollback lost a file added after the apply: %s = %q\n%s", added, got, out.String())
	}
	if got := read(t, filepath.Join(d, "inner.txt")); got != "agent\n" {
		t.Errorf("the directory is not left as is: the agent's inner.txt = %q\n%s", got, out.String())
	}
	if want := "left as is (holds files added or changed after the apply): " + d; !strings.Contains(out.String(), want) {
		t.Errorf("output lacks %q: %s", want, out.String())
	}
	if _, prev := keptVersion(t, s, d); prev != "user file\n" {
		t.Fatalf("version of %s from before the apply = %q", d, prev)
	}
}

// A file inside a replaced directory that the rollback leaves, because
// the user edited it after the apply, is not deleted when the rollback
// reaches the directory.
func TestRollbackKeepsLaterEditInsideReplacedDir(t *testing.T) {
	s, d := appliedReplacedDir(t, "inner.txt")
	inner := filepath.Join(d, "inner.txt")
	if err := os.WriteFile(inner, []byte("edited after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if got := read(t, inner); got != "edited after\n" {
		t.Fatalf("rollback lost a file it had left: %s = %q\n%s", inner, got, out.String())
	}
	for _, want := range []string{
		"left as is (changed after the apply): " + inner,
		"left as is (holds files added or changed after the apply): " + d,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q: %s", want, out.String())
		}
	}
	if _, prev := keptVersion(t, s, d); prev != "user file\n" {
		t.Fatalf("version of %s from before the apply = %q", d, prev)
	}
}

// A replaced directory holding a directory the apply created inside it
// is restored in one rollback: once that directory is gone (it is
// empty), so is the replaced one, and the user's file is back.
func TestRollbackRestoresReplacedDirWithSubdir(t *testing.T) {
	s, d := appliedReplacedDir(t, filepath.Join("sub", "inner.txt"))
	var out bytes.Buffer
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if got := read(t, d); got != "user file\n" {
		t.Fatalf("%s not restored: %q\n%s", d, got, out.String())
	}
	if _, err := os.Lstat(filepath.Join(d, "sub")); err == nil {
		t.Errorf("the agent's directory %s/sub was not rolled back", d)
	}
	if strings.Contains(out.String(), "left as is") {
		t.Errorf("rollback left paths although nothing changed after the apply:\n%s", out.String())
	}
	if gs, err := listGenerations(s); err != nil || len(gs) != 0 {
		t.Fatalf("rollback not complete: generations %v (%v)\n%s", gs, err, out.String())
	}
}

// A file the user puts after the apply where the apply had made a
// directory, inside a replaced directory, survives the rollback; the
// replaced directory stays, with the user's file from before the apply
// kept.
func TestRollbackKeepsFileInPlaceOfMadeDir(t *testing.T) {
	s, d := appliedReplacedDir(t, filepath.Join("sub", "inner.txt"))
	sub := filepath.Join(d, "sub")
	if err := os.RemoveAll(sub); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sub, []byte("user's own\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if got := read(t, sub); got != "user's own\n" {
		t.Fatalf("rollback lost a file the user put in place of a directory it made: %s = %q\n%s", sub, got, out.String())
	}
	if want := "left as is (holds files added or changed after the apply): " + d; !strings.Contains(out.String(), want) {
		t.Errorf("output lacks %q: %s", want, out.String())
	}
	if _, prev := keptVersion(t, s, d); prev != "user file\n" {
		t.Fatalf("version of %s from before the apply = %q", d, prev)
	}
}

// A partial rollback keeps the version from before the apply of each
// path it left, and a second rollback neither fails nor loses it.
func TestPartialRollbackKeepsPreviousVersion(t *testing.T) {
	s, box := undoSession(t)
	ws := s.Workspace
	mod := filepath.Join(ws, "mod.txt")
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Force: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if err := os.WriteFile(mod, []byte("edited after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for round := 1; round <= 2; round++ {
		out.Reset()
		if err := Rollback(s, nil, &out); err != nil {
			t.Fatalf("rollback %d: %v\n%s", round, err, out.String())
		}
		if got := read(t, mod); got != "edited after\n" {
			t.Fatalf("rollback %d overwrote a later edit: %q", round, got)
		}
		g, prev := keptVersion(t, s, mod)
		if prev != "user\n" {
			t.Fatalf("rollback %d: version of mod.txt from before the apply = %q", round, prev)
		}
		var journal struct {
			Partial bool `json:"partial"`
		}
		if b, err := os.ReadFile(filepath.Join(g.dir, "journal.json")); err != nil || json.Unmarshal(b, &journal) != nil {
			t.Fatalf("rollback %d: read the journal: %v", round, err)
		}
		if !journal.Partial || len(g.Entries) != 1 {
			t.Fatalf("rollback %d: generation not trimmed to the path left: partial=%v entries=%+v", round, journal.Partial, g.Entries)
		}
		saved := g.Entries[0].Saved
		if !strings.HasPrefix(saved, filepath.Join(g.dir, "saved")+string(filepath.Separator)) {
			t.Errorf("rollback %d: previous version kept outside the generation: %s", round, saved)
		}
		if want := "its version from before the apply is kept at " + saved; !strings.Contains(out.String(), want) {
			t.Errorf("rollback %d: output lacks %q: %s", round, want, out.String())
		}
	}
	// The rest was rolled back by the first round.
	if read(t, filepath.Join(ws, "del.txt")) != "keep me\n" {
		t.Fatal("del.txt not restored")
	}
	if _, err := os.Stat(filepath.Join(ws, "sub")); err == nil {
		t.Fatal("sub/ left behind")
	}
}

// A directory the apply made inside a replaced directory, which the
// first rollback cannot remove because the user put a file in it, is
// still known as the apply's: once the user removes that file, a second
// rollback takes it out and restores the user's original.
func TestRollbackRetryRestoresReplacedDirAfterUserCleansSubdir(t *testing.T) {
	s, d := appliedReplacedDir(t, filepath.Join("sub", "inner.txt"))
	added := filepath.Join(d, "sub", "user.txt")
	if err := os.WriteFile(added, []byte("added after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if got := read(t, added); got != "added after\n" {
		t.Fatalf("rollback lost a file added after the apply: %s = %q\n%s", added, got, out.String())
	}
	if want := "left as is (holds files added or changed after the apply): " + d; !strings.Contains(out.String(), want) {
		t.Errorf("output lacks %q: %s", want, out.String())
	}
	if _, prev := keptVersion(t, s, d); prev != "user file\n" {
		t.Fatalf("version of %s from before the apply = %q", d, prev)
	}
	if err := os.Remove(added); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if got := read(t, d); got != "user file\n" {
		t.Fatalf("second rollback did not restore %s: %q\n%s", d, got, out.String())
	}
	if gs, err := listGenerations(s); err != nil || len(gs) != 0 {
		t.Fatalf("second rollback not complete: generations %v (%v)\n%s", gs, err, out.String())
	}
}

// A directory the apply made, which a rollback cannot remove because
// the user put a file in it, is still known as the apply's while the
// generation is kept for another path: once the user removes the file,
// the next rollback takes the directory out.
func TestRollbackRetryRemovesMadeDirAfterUserCleansIt(t *testing.T) {
	s, box := undoSession(t)
	ws := s.Workspace
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Force: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	// mod.txt keeps the generation; sub/ is a directory the apply made.
	if err := os.WriteFile(filepath.Join(ws, "mod.txt"), []byte("edited after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	added := filepath.Join(ws, "sub", "user.txt")
	if err := os.WriteFile(added, []byte("added after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if got := read(t, added); got != "added after\n" {
		t.Fatalf("rollback lost a file added after the apply: %q\n%s", got, out.String())
	}
	if err := os.Remove(added); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if _, err := os.Lstat(filepath.Join(ws, "sub")); err == nil {
		t.Fatalf("second rollback left the directory the apply made, now empty:\n%s", out.String())
	}
	if got := read(t, filepath.Join(ws, "mod.txt")); got != "edited after\n" {
		t.Fatalf("rollback overwrote a later edit: %q", got)
	}
}

// appliedOverlayReplacedDir lays out an overlay session in which the
// agent replaced the user's directory src (a.go, b.go) with one holding
// new.go, as `rm -rf src` and a new src would, and applies it. It
// returns the real path of src.
func appliedOverlayReplacedDir(t *testing.T) (*session.Session, string) {
	t.Helper()
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := filepath.Join(t.TempDir(), "ws")
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	for p, data := range map[string]string{
		filepath.Join(ws, "src", "a.go"):            "package a\n",
		filepath.Join(ws, "src", "b.go"):            "package b\n",
		filepath.Join(s.WSUpper(), "src", "new.go"): "package new\n",
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Setxattr(filepath.Join(s.WSUpper(), "src"), "user.overlay.opaque", []byte("y"), 0); err != nil {
		t.Skipf("cannot mark a directory opaque here: %v", err)
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = box.Close() })
	if got := scan(t, s); got["src"] != review.Replaced || got[filepath.Join("src", "new.go")] != review.Added {
		t.Fatalf("scan %v", got)
	}
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Force: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	src := filepath.Join(ws, "src")
	if read(t, filepath.Join(src, "new.go")) != "package new\n" {
		t.Fatal("replaced directory not applied")
	}
	return s, src
}

// A file a tool drops into a replaced directory after the apply keeps
// the directory as the apply left it: the agent's files stay next to
// it, and the user's directory from before the apply is kept whole.
// Once the file is gone, the next rollback restores the user's version.
func TestRollbackLeavesReplacedDirWhole(t *testing.T) {
	s, src := appliedOverlayReplacedDir(t)
	pyc := filepath.Join(src, "__pycache__", "x.pyc")
	if err := os.MkdirAll(filepath.Dir(pyc), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pyc, []byte("cache\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if got := read(t, filepath.Join(src, "new.go")); got != "package new\n" {
		t.Fatalf("rollback said it left %s as is, but took the agent's new.go out: %q\n%s", src, got, out.String())
	}
	if got := read(t, pyc); got != "cache\n" {
		t.Fatalf("rollback lost a file added after the apply: %q", got)
	}
	if want := "left as is (holds files added or changed after the apply): " + src; !strings.Contains(out.String(), want) {
		t.Errorf("output lacks %q: %s", want, out.String())
	}
	g, _ := keptVersion(t, s, src)
	for _, e := range g.Entries {
		if e.Path == src {
			if read(t, filepath.Join(e.Saved, "a.go")) != "package a\n" || read(t, filepath.Join(e.Saved, "b.go")) != "package b\n" {
				t.Fatalf("the user's src from before the apply is not kept whole at %s", e.Saved)
			}
		}
	}
	if err := os.RemoveAll(filepath.Dir(pyc)); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if read(t, filepath.Join(src, "a.go")) != "package a\n" || read(t, filepath.Join(src, "b.go")) != "package b\n" {
		t.Fatalf("second rollback did not restore the user's src:\n%s", out.String())
	}
	if _, err := os.Lstat(filepath.Join(src, "new.go")); err == nil {
		t.Errorf("the agent's new.go is still in the restored src")
	}
	if gs, err := listGenerations(s); err != nil || len(gs) != 0 {
		t.Fatalf("second rollback not complete: generations %v (%v)\n%s", gs, err, out.String())
	}
}

// crashAt turns the last generation of s into one that stopped while
// copying path: the step is unfinished, path is not there, and the
// temp file copyFile was writing is left next to it.
func crashAt(t *testing.T, s *session.Session, path string) string {
	t.Helper()
	stopAt(t, s, path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(filepath.Dir(path), ".airbag-2918374650")
	if err := os.WriteFile(tmp, []byte("half of the agent's"), 0o600); err != nil {
		t.Fatal(err)
	}
	return tmp
}

// stopAt turns the last generation of s into one that stopped at the
// step for path: the journal does not record it as done.
func stopAt(t *testing.T, s *session.Session, path string) {
	t.Helper()
	gs, err := listGenerations(s)
	if err != nil || len(gs) == 0 {
		t.Fatal("no generation", err)
	}
	g, err := loadGeneration(gs[len(gs)-1].dir)
	if err != nil {
		t.Fatal(err)
	}
	g.Complete = false
	for i := range g.Entries {
		if g.Entries[i].Path == path {
			g.Entries[i].After = ""
		}
	}
	if err := g.save(); err != nil {
		t.Fatal(err)
	}
}

// A temp file an apply that was stopped left inside a replaced
// directory is the apply's, not the user's: rollback removes it and
// restores the user's version.
func TestRollbackRemovesApplyTempInReplacedDir(t *testing.T) {
	s, d := appliedReplacedDir(t, filepath.Join("sub", "inner.txt"))
	crashAt(t, s, filepath.Join(d, "sub", "inner.txt"))
	var out bytes.Buffer
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if got := read(t, d); got != "user file\n" {
		t.Fatalf("%s not restored: %q\n%s", d, got, out.String())
	}
	if gs, err := listGenerations(s); err != nil || len(gs) != 0 {
		t.Fatalf("rollback not complete: generations %v (%v)\n%s", gs, err, out.String())
	}
}

// Only a temp file named as copyFile names them, in the directory of a
// copy step that did not finish, counts as the apply's; a user's file
// with a similar name keeps the directory as it is.
func TestRollbackKeepsUserFileNamedLikeTemp(t *testing.T) {
	for _, name := range []string{".airbag-notes", filepath.Join("own", ".airbag-123")} {
		s, d := appliedReplacedDir(t, "inner.txt")
		p := filepath.Join(d, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("mine\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := Rollback(s, nil, &out); err != nil {
			t.Fatal(err, out.String())
		}
		if got := read(t, p); got != "mine\n" {
			t.Fatalf("rollback removed the user's %s: %q\n%s", name, got, out.String())
		}
		if _, prev := keptVersion(t, s, d); prev != "user file\n" {
			t.Fatalf("version of %s from before the apply = %q", d, prev)
		}
	}
}

// A replaced directory with no previous version (what it replaced was
// gone by the time of the apply) is removed by rollback only once it is
// empty: a file the user adds to it afterwards survives.
func TestRollbackKeepsFileInReplacedDirWithoutPrevious(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := filepath.Join(t.TempDir(), "ws")
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	d := filepath.Join(ws, "d")
	for p, data := range map[string]string{d: "user file\n", filepath.Join(s.CloneDir(), "d", "inner.txt"): "agent\n"} {
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
	defer func() { _ = box.Close() }()
	cs := mustScan(t, s)
	if err := os.Remove(d); err != nil { // gone before the apply
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Apply(s, cs, box, Options{Yes: true, Force: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	g, _ := loadGeneration(filepath.Join(s.Dir, "undo", "1"))
	if len(g.Entries) == 0 || g.Entries[0].Path != d || g.Entries[0].Kind != review.Replaced || g.Entries[0].Saved != "" {
		t.Fatalf("setup: want a replaced %s with no previous version: %+v", d, g.Entries)
	}
	added := filepath.Join(d, "user.txt")
	if err := os.WriteFile(added, []byte("added after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if got := read(t, added); got != "added after\n" {
		t.Fatalf("rollback lost a file added after the apply: %s = %q\n%s", added, got, out.String())
	}
	if _, err := os.Lstat(filepath.Join(d, "inner.txt")); err == nil {
		t.Errorf("the agent's inner.txt was not rolled back")
	}
}

// A step that did not finish and had no previous version to move away
// removes what is at its path only when that is the agent's version: a
// file the user wrote there after the apply stopped survives.
func TestRollbackKeepsUserFileAtUnfinishedStep(t *testing.T) {
	for _, tc := range []struct {
		data string
		kept bool
	}{{"the user's own\n", true}, {"new\n", false}} {
		s, box := undoSession(t)
		var out bytes.Buffer
		if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Force: true, Out: &out}); err != nil {
			t.Fatal(err, out.String())
		}
		p := filepath.Join(s.Workspace, "sub", "new.txt")
		stopAt(t, s, p)
		// A stopped apply never got to forget the agent's version.
		if err := os.WriteFile(filepath.Join(s.WSUpper(), "sub", "new.txt"), []byte("new\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(tc.data), 0o644); err != nil {
			t.Fatal(err)
		}
		out.Reset()
		if err := Rollback(s, nil, &out); err != nil {
			t.Fatal(err, out.String())
		}
		got := read(t, p)
		switch {
		case tc.kept && got != tc.data:
			t.Fatalf("rollback lost a file the user wrote after the apply stopped: %q\n%s", got, out.String())
		case !tc.kept && got == tc.data:
			t.Fatalf("rollback left the agent's version of an unfinished step:\n%s", out.String())
		}
	}
}

// overlayReplacedDir lays out an overlay session in which the agent
// replaced the user's directory src, holding the files real, with one
// holding the files agent; both also hold a symlink link to a.go. It
// returns the real path of src.
func overlayReplacedDir(t *testing.T, real, agent map[string]string) (*session.Session, *outbox.Box, string) {
	t.Helper()
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := filepath.Join(t.TempDir(), "ws")
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	src, up := filepath.Join(ws, "src"), filepath.Join(s.WSUpper(), "src")
	for dir, files := range map[string]map[string]string{src: real, up: agent} {
		for rel, data := range files {
			p := filepath.Join(dir, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink("a.go", filepath.Join(dir, "link")); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Setxattr(up, "user.overlay.opaque", []byte("y"), 0); err != nil {
		t.Skipf("cannot mark a directory opaque here: %v", err)
	}
	s.Baseline = time.Now() // the real files are from before the session
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = box.Close() })
	return s, box, src
}

// When the agent replaces a directory (opaque in the upper layer), the
// apply writes all of the agent's version, files the same as before
// included, and nothing of the user's: the directory is what the agent
// saw. Rollback brings the user's back.
func TestApplyWritesAllOfReplacedDir(t *testing.T) {
	s, box, src := overlayReplacedDir(t, map[string]string{
		"a.go":     "package a\n",
		"b.go":     "package b\n",
		"sub/c.go": "package c\n",
	}, map[string]string{
		"a.go":     "package a\n", // the same as before
		"new.go":   "package new\n",
		"sub/c.go": "package c\n", // the same, in a directory not marked
	})
	if cf := Conflicts(s, mustScan(t, s)); len(cf) > 0 {
		t.Fatalf("conflicts although nothing changed on the host: %+v", cf)
	}
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	for rel, want := range map[string]string{"a.go": "package a\n", "new.go": "package new\n", "sub/c.go": "package c\n"} {
		if got := read(t, filepath.Join(src, rel)); got != want {
			t.Errorf("after the apply src/%s = %q, want the agent's %q", rel, got, want)
		}
	}
	if l, err := os.Readlink(filepath.Join(src, "link")); err != nil || l != "a.go" {
		t.Errorf("after the apply src/link = %q (%v), want the agent's link to a.go", l, err)
	}
	if _, err := os.Lstat(filepath.Join(src, "b.go")); err == nil {
		t.Errorf("src/b.go, which the agent's src does not have, is still there")
	}
	out.Reset()
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	for rel, want := range map[string]string{"a.go": "package a\n", "b.go": "package b\n", "sub/c.go": "package c\n"} {
		if got := read(t, filepath.Join(src, rel)); got != want {
			t.Errorf("after the rollback src/%s = %q, want the user's %q\n%s", rel, got, want, out.String())
		}
	}
	if _, err := os.Lstat(filepath.Join(src, "new.go")); err == nil {
		t.Errorf("src/new.go still there after the rollback")
	}
	if gs, err := listGenerations(s); err != nil || len(gs) != 0 {
		t.Fatalf("rollback not complete: generations %v (%v)\n%s", gs, err, out.String())
	}
}

// A file of the agent's that the user removed after the apply, from a
// replaced directory, is not kept by rollback as "changed": nothing was
// there before the apply either. Kept, it would match the user's own
// file, the same as the agent's, once the directory is restored, and a
// later rollback would remove that file.
func TestRollbackKeepsUserFileSameAsAgentsRemovedOne(t *testing.T) {
	s, box, src := overlayReplacedDir(t,
		map[string]string{"a.go": "package a\n", "b.go": "package b\n"},
		map[string]string{"a.go": "package a\n", "new.go": "package new\n"})
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	a := filepath.Join(src, "a.go")
	if err := os.Remove(a); err != nil {
		t.Fatal(err)
	}
	for round := 1; round <= 2; round++ {
		out.Reset()
		if err := Rollback(s, nil, &out); err != nil && round == 1 {
			t.Fatal(err, out.String())
		}
		if got := read(t, a); got != "package a\n" {
			t.Fatalf("after rollback %d the user's src/a.go = %q\n%s", round, got, out.String())
		}
	}
	if gs, err := listGenerations(s); err != nil || len(gs) != 0 {
		t.Fatalf("rollback not complete: generations %v (%v)", gs, err)
	}
}

// Temp files are removed only from a replaced directory checked to hold
// nothing but the apply's: when its previous version is gone from the
// session, a user's file that looks like one stays.
func TestRollbackRemovesTempsOnlyFromCheckedDir(t *testing.T) {
	s, d := appliedReplacedDir(t, "inner.txt")
	g, _ := keptVersion(t, s, d)
	if err := os.RemoveAll(g.Entries[0].Saved); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, ".airbag-123")
	if err := os.WriteFile(p, []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if got := read(t, p); got != "mine\n" {
		t.Fatalf("rollback removed the user's %s: %q\n%s", p, got, out.String())
	}
}

// After a rollback, a directory the agent replaced is opaque again in
// the session, though the paths inside it are given back first: review
// shows the replacement, and applying it again gives the agent's
// version only.
func TestRollbackKeepsReplacedDirOpaque(t *testing.T) {
	s, box, src := overlayReplacedDir(t,
		map[string]string{"a.go": "package a\n", "b.go": "package b\n"},
		map[string]string{"a.go": "package a\n", "new.go": "package new\n"})
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	out.Reset()
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if read(t, filepath.Join(src, "b.go")) != "package b\n" {
		t.Fatalf("rollback did not restore the user's src:\n%s", out.String())
	}
	up := filepath.Join(s.WSUpper(), "src")
	buf := make([]byte, 8)
	if n, err := unix.Getxattr(up, "user.overlay.opaque", buf); err != nil || n == 0 || buf[0] != 'y' {
		t.Errorf("%s is not opaque after the rollback (%v): the session would merge it with the user's src", up, err)
	}
	if got := scan(t, s); got["src"] != review.Replaced || got[filepath.Join("src", "new.go")] != review.Added {
		t.Fatalf("review does not show the replacement again: %v", got)
	}
	out.Reset()
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Force: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	for rel, want := range map[string]string{"a.go": "package a\n", "new.go": "package new\n"} {
		if got := read(t, filepath.Join(src, rel)); got != want {
			t.Errorf("after the second apply src/%s = %q, want the agent's %q", rel, got, want)
		}
	}
	if _, err := os.Lstat(filepath.Join(src, "b.go")); err == nil {
		t.Errorf("the second apply kept src/b.go, which the agent's src does not have")
	}
}

// A finished apply leaves no temp file: after one, a file named like
// copyFile's temp files in a replaced directory the apply copied into
// is the user's. Rollback keeps it and leaves the directory as it is.
func TestRollbackKeepsTempNamedFileAfterFinishedApply(t *testing.T) {
	s, d := appliedReplacedDir(t, "inner.txt")
	p := filepath.Join(d, ".airbag-123")
	if err := os.WriteFile(p, []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if got := read(t, p); got != "mine\n" {
		t.Fatalf("rollback removed the user's %s: %q\n%s", p, got, out.String())
	}
	if want := "left as is (holds files added or changed after the apply): " + d; !strings.Contains(out.String(), want) {
		t.Errorf("output lacks %q: %s", want, out.String())
	}
	if _, prev := keptVersion(t, s, d); prev != "user file\n" {
		t.Fatalf("version of %s from before the apply = %q", d, prev)
	}
}

// An agent config that was in the real $HOME when a run began and that
// the host removed since reads as a new file in the branch; apply
// reports the removal instead of bringing the old settings back. A
// config that was never there is an ordinary new file.
func TestConflictConfigRemovedOnHost(t *testing.T) {
	for _, existed := range []bool{true, false} {
		t.Setenv("AIRBAG_HOME", t.TempDir())
		home := t.TempDir()
		s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: home, OverHome: true})
		if err != nil {
			t.Fatal(err)
		}
		real := filepath.Join(home, ".claude.json")
		if existed {
			if err := os.WriteFile(real, []byte(`{"mcpServers":{"x":{}}}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		review.NoteHostConfigs(s)
		branch := filepath.Join(s.HomeUpper(), ".claude.json")
		if err := os.MkdirAll(filepath.Dir(branch), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(branch, []byte(`{"mcpServers":{"x":{}},"numStartups":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if existed {
			if err := os.Remove(real); err != nil {
				t.Fatal(err)
			}
		}
		var found bool
		for _, c := range Conflicts(s, mustScan(t, s)) {
			found = found || c.Path == real && c.Reason == "deleted on the host during the session"
		}
		if found != existed {
			t.Errorf("existed at the run's start=%v: conflict=%v", existed, found)
		}
	}
}

// A config deletion airbag itself applied is not a host removal: when a
// later run of the session creates the config anew, apply takes it.
func TestAppliedConfigDeletionIsNotAHostRemoval(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home := t.TempDir()
	real := filepath.Join(home, ".claude.json")
	if err := os.WriteFile(real, []byte(`{"numStartups":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	review.NoteHostConfigs(s)
	branch := filepath.Join(s.HomeUpper(), ".claude.json")
	if err := os.MkdirAll(filepath.Dir(branch), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mknod(branch, syscall.S_IFCHR, 0); err != nil {
		t.Skipf("cannot create a whiteout here: %v", err)
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = box.Close() })
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if _, err := os.Lstat(real); !os.IsNotExist(err) {
		t.Fatalf("apply did not remove the config: %v", err)
	}
	// The next run: the host has no config, and the agent writes one.
	review.NoteHostConfigs(s)
	if err := os.WriteFile(branch, []byte(`{"numStartups":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if cf := Conflicts(s, mustScan(t, s)); len(cf) != 0 {
		t.Fatalf("conflicts for a config the agent created after an applied deletion: %v", cf)
	}
}

// A config removed with the directory above it, by an applied deletion
// of ~/.claude, is not one the host removed either.
func TestAppliedDirDeletionClearsHostConfig(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home := t.TempDir()
	legacy := filepath.Join(home, ".claude/.config.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte(`{"numStartups":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	review.NoteHostConfigs(s)
	if !slices.Contains(s.HostConfigs, legacy) {
		t.Fatalf("not noted: %v", s.HostConfigs)
	}
	dir := filepath.Join(s.HomeUpper(), ".claude")
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mknod(dir, syscall.S_IFCHR, 0); err != nil {
		t.Skipf("cannot create a whiteout here: %v", err)
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = box.Close() })
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if slices.Contains(s.HostConfigs, legacy) {
		t.Errorf("still noted after the applied deletion: %v", s.HostConfigs)
	}
	review.NoteHostConfigs(s)
	branch := filepath.Join(s.HomeUpper(), ".claude/.config.json")
	if err := os.MkdirAll(filepath.Dir(branch), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(branch, []byte(`{"numStartups":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if cf := Conflicts(s, mustScan(t, s)); len(cf) != 0 {
		t.Fatalf("conflicts for a config the agent created after an applied deletion: %v", cf)
	}
}

// So is one removed by a link put in place of the directory above it,
// which Scan calls Modified.
func TestAppliedLinkOverDirClearsHostConfig(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home := t.TempDir()
	legacy := filepath.Join(home, ".claude/.config.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte(`{"numStartups":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	review.NoteHostConfigs(s)
	if err := os.MkdirAll(s.HomeUpper(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "elsewhere"), filepath.Join(s.HomeUpper(), ".claude")); err != nil {
		t.Fatal(err)
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = box.Close() })
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if slices.Contains(s.HostConfigs, legacy) {
		t.Errorf("still noted after a link replaced ~/.claude: %v", s.HostConfigs)
	}
}

// What review folds in $HOME (a cache, agent state) is left out by
// apply, a cache whatever it holds; flagged agent state (memory) is
// applied; --only takes a folded path only when written as a $HOME one.
// What is left out does not keep the session open.
func TestApplyLeavesFoldsOut(t *testing.T) {
	for _, only := range [][]string{nil, {"~/.cache/tool/x"}, {".cache/tool/x"}} {
		t.Setenv("AIRBAG_HOME", t.TempDir())
		home := t.TempDir()
		s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: home, OverHome: true})
		if err != nil {
			t.Fatal(err)
		}
		s.Status = session.StatusStopped
		for f, mode := range map[string]os.FileMode{".cache/tool/x": 0o600, ".cache/tool/bin/run": 0o755,
			"notes.txt": 0o600, ".claude/projects/p/memory/MEMORY.md": 0o600} {
			p := filepath.Join(s.HomeUpper(), f)
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("x"), mode); err != nil {
				t.Fatal(err)
			}
		}
		box, err := outbox.Open(s.EffectsPath())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = box.Close() })
		var out bytes.Buffer
		err = Apply(s, mustScan(t, s), box, Options{Yes: true, Only: only, Out: &out})
		exists := func(f string) bool { _, err := os.Stat(filepath.Join(home, f)); return err == nil }
		switch {
		case only == nil:
			if err != nil {
				t.Fatal(err, out.String())
			}
			if exists(".cache/tool/x") || exists(".cache/tool/bin/run") || !exists("notes.txt") || !exists(".claude/projects/p/memory/MEMORY.md") {
				t.Errorf("default apply: cache %v, executable %v, notes %v, memory %v\n%s", exists(".cache/tool/x"),
					exists(".cache/tool/bin/run"), exists("notes.txt"), exists(".claude/projects/p/memory/MEMORY.md"), out.String())
			}
			if s.Status != session.StatusApplied {
				t.Errorf("status %s after an apply that left only folds out:\n%s", s.Status, out.String())
			}
		case only[0] == "~/.cache/tool/x":
			if err != nil || !exists(".cache/tool/x") {
				t.Errorf("--only ~/... did not take the cache file: %v\n%s", err, out.String())
			}
		default:
			if err == nil || exists(".cache/tool/x") {
				t.Errorf("--only in workspace form took the $HOME cache file: %v\n%s", err, out.String())
			}
		}
	}
}

// A folded change under a directory the agent replaced goes with the
// replacement: applying it takes the host's directory away.
func TestApplyKeepsFoldsUnderReplacedDir(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude/todos"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude/todos/old.json"), []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	up := filepath.Join(s.HomeUpper(), ".claude")
	if err := os.MkdirAll(filepath.Join(up, "todos"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(up, "user.overlay.opaque", []byte("y"), 0); err != nil {
		t.Skipf("cannot mark a directory opaque here: %v", err)
	}
	if err := os.WriteFile(filepath.Join(up, "todos/new.json"), []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = box.Close() })
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".claude/todos/new.json")); err != nil {
		t.Errorf("the replaced ~/.claude lost its folded todos: %v\n%s", err, out.String())
	}
}

// A cache under a directory the agent replaced (rm -rf ~/.m2, then a
// build) is still left out: the agent's jars do not reach the host.
func TestApplyDropsCacheUnderReplacedDir(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home := t.TempDir()
	jar := ".m2/repository/g/a/1/a-1.jar"
	if err := os.MkdirAll(filepath.Dir(filepath.Join(home, jar)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, jar), []byte("host"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	up := filepath.Join(s.HomeUpper(), ".m2")
	if err := os.MkdirAll(filepath.Dir(filepath.Join(s.HomeUpper(), jar)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(up, "user.overlay.opaque", []byte("y"), 0); err != nil {
		t.Skipf("cannot mark a directory opaque here: %v", err)
	}
	if err := os.WriteFile(filepath.Join(s.HomeUpper(), jar), []byte("agent"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(up, "wrapper"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(up, "wrapper/w.properties"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = box.Close() })
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if b, err := os.ReadFile(filepath.Join(home, jar)); err == nil && string(b) == "agent" {
		t.Errorf("the agent's jar reached the host under a replaced ~/.m2\n%s", out.String())
	}
	// What was applied stays on a second apply, and the session is done.
	if s.Status != session.StatusApplied {
		t.Errorf("status %s with only a left-out cache in the session\n%s", s.Status, out.String())
	}
	out.Reset()
	s.Status = session.StatusStopped
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".m2/wrapper/w.properties")); err != nil {
		t.Errorf("a second apply took away what the first wrote: %v\n%s", err, out.String())
	}
}

// A config that is a link into $HOME: the agent's write lands on the
// link's target, and if the host removes that target during the session,
// apply reports it rather than bringing it back.
func TestConflictLinkedConfigRemovedOnHost(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home := t.TempDir()
	target := filepath.Join(home, "dotfiles", "claude.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dotfiles/claude.json", filepath.Join(home, ".claude.json")); err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	review.NoteHostConfigs(s)
	branch := filepath.Join(s.HomeUpper(), "dotfiles", "claude.json")
	if err := os.MkdirAll(filepath.Dir(branch), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(branch, []byte(`{"mcpServers":{"x":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range Conflicts(s, mustScan(t, s)) {
		found = found || c.Path == target && c.Reason == "deleted on the host during the session"
	}
	if !found {
		t.Fatal("no conflict for a linked config's target the host removed")
	}
}

// A config linked into the workspace (a dotfiles repository the agent
// works in): the target the host removes during the session is a
// conflict too.
func TestConflictConfigLinkedIntoWorkspace(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home, ws := t.TempDir(), t.TempDir()
	target := filepath.Join(ws, "claude.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, ".claude.json")); err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	review.NoteHostConfigs(s)
	if err := os.MkdirAll(s.WSUpper(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.WSUpper(), "claude.json"), []byte(`{"mcpServers":{"x":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range Conflicts(s, mustScan(t, s)) {
		found = found || c.Path == target && c.Reason == "deleted on the host during the session"
	}
	if !found {
		t.Fatal("no conflict for a config's workspace target the host removed")
	}
}

// A file an earlier, partial apply wrote, which a later run changes
// again in the branch, does not conflict: that write was airbag's, not
// the host's. A host edit after it still does.
func TestPartialApplyThenRunAgain(t *testing.T) {
	s, box := undoSession(t)
	time.Sleep(20 * time.Millisecond)
	s.Baseline = time.Now() // the real files were there before the run
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Only: []string{"mod.txt"}, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	real := filepath.Join(s.Workspace, "mod.txt")
	if got := read(t, real); got != "agent\n" {
		t.Fatalf("mod.txt = %q", got)
	}
	// The next run changes it again.
	if err := os.WriteFile(filepath.Join(s.WSUpper(), "mod.txt"), []byte("agent again\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if cf := Conflicts(s, mustScan(t, s)); len(cf) != 0 {
		t.Fatalf("conflicts after the apply's own write: %v", cf)
	}
	time.Sleep(20 * time.Millisecond) // past the clock's tick
	if err := os.WriteFile(real, []byte("host edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cf := Conflicts(s, mustScan(t, s))
	if len(cf) != 1 || cf[0].Path != real {
		t.Fatalf("a host edit after the apply: conflicts %v", cf)
	}
}

// A new directory that holds only links (node_modules/.bin) is applied:
// it is made along with its links, as with files.
func TestApplyNewDirectoryOfLinks(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := filepath.Join(t.TempDir(), "ws")
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	if err := os.MkdirAll(filepath.Join(s.CloneDir(), "node_modules/.bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../tool/cli.js", filepath.Join(s.CloneDir(), "node_modules/.bin/tool")); err != nil {
		t.Fatal(err)
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Force: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if target, err := os.Readlink(filepath.Join(ws, "node_modules/.bin/tool")); err != nil || target != "../tool/cli.js" {
		t.Fatalf("link not applied: %q %v", target, err)
	}
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if _, err := os.Lstat(filepath.Join(ws, "node_modules")); err == nil {
		t.Fatal("rollback left the directories it made")
	}
}

// A directory the host turned into a link while the session ran does
// not carry the agent's changes out: nothing is written or removed where
// it leads.
func TestApplyRefusesLinkedParent(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	upper := t.TempDir()
	if err := os.WriteFile(filepath.Join(upper, "f"), []byte("agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../tool/cli.js", filepath.Join(upper, "l")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "keep"), []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "dir")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []review.Change{
		{Layer: "ws", Rel: "dir/f", Path: filepath.Join(root, "dir/f"), Upper: filepath.Join(upper, "f"), Kind: review.Added, Mode: 0o644},
		{Layer: "ws", Rel: "dir/sub/l", Path: filepath.Join(root, "dir/sub/l"), Upper: filepath.Join(upper, "l"), Kind: review.Added, Type: fs.ModeSymlink},
		{Layer: "ws", Rel: "dir/keep", Path: filepath.Join(root, "dir/keep"), Kind: review.Deleted},
	} {
		if err := applyOne(c); err == nil || !strings.Contains(err.Error(), "became a link") {
			t.Errorf("%s %s: %v", c.Kind, c.Rel, err)
		}
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 1 || entries[0].Name() != "keep" {
		t.Fatalf("changed what the link leads to: %v", entries)
	}
}

// The check comes before the undo journal moves the previous version
// away: through Apply nothing is applied, and through a generation the
// file the link leads to never leaves its place.
func TestApplyRefusesLinkedParentBeforeJournal(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := filepath.Join(t.TempDir(), "ws")
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	outside := t.TempDir()
	keep := filepath.Join(outside, "keep")
	if err := os.WriteFile(keep, []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(ws, "dir")); err != nil {
		t.Fatal(err)
	}
	upper := filepath.Join(t.TempDir(), "keep")
	if err := os.WriteFile(upper, []byte("agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cs := []review.Change{
		{Layer: "ws", Rel: "dir/keep", Path: filepath.Join(ws, "dir/keep"), Upper: upper, Kind: review.Modified, Mode: 0o644},
		{Layer: "ws", Rel: "dir/keep", Path: filepath.Join(ws, "dir/keep"), Kind: review.Deleted},
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	var out bytes.Buffer
	for _, c := range cs {
		if err := Apply(s, []review.Change{c}, box, Options{Yes: true, Force: true, Out: &out}); err == nil || !strings.Contains(err.Error(), "became a link") {
			t.Fatalf("%s applied through a linked parent: %v", c.Kind, err)
		}
	}
	g, err := beginGeneration(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if err := g.apply(c); err == nil {
			t.Fatalf("%s: the generation applied through a linked parent", c.Kind)
		}
		if data, err := os.ReadFile(keep); err != nil || string(data) != "mine\n" {
			t.Fatalf("%s: the file the link leads to moved: %q %v", c.Kind, data, err)
		}
	}
}

// moveRoot does what Codex's case describes: the host renames the
// workspace and puts a link to another directory at its path.
func moveRoot(t *testing.T, ws string) (elsewhere string) {
	t.Helper()
	elsewhere = t.TempDir()
	if err := os.Rename(ws, ws+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, ws); err != nil {
		t.Fatal(err)
	}
	return elsewhere
}

func rootSession(t *testing.T, ws string) *session.Session {
	t.Helper()
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home := t.TempDir()
	wsID, err := session.DirIDOf(ws)
	if err != nil {
		t.Fatal(err)
	}
	homeID, err := session.DirIDOf(home)
	if err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, WorkspaceID: wsID, HomeID: homeID, Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	return s
}

// A workspace that leads elsewhere than when the session began takes no
// change, a new top-level file included: no parent below the root is a
// link, so only the root itself shows it.
func TestApplyRefusesMovedRoot(t *testing.T) {
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	s := rootSession(t, ws)
	upper := filepath.Join(t.TempDir(), "new.txt")
	if err := os.WriteFile(upper, []byte("agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := review.Change{Layer: "ws", Rel: "new.txt", Path: filepath.Join(ws, "new.txt"), Upper: upper, Kind: review.Added, Mode: 0o644}
	elsewhere := moveRoot(t, ws)
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	var out bytes.Buffer
	if err := Apply(s, []review.Change{c}, box, Options{Yes: true, Force: true, Out: &out}); err == nil || !strings.Contains(err.Error(), "leads to") {
		t.Fatalf("applied through a moved root: %v", err)
	}
	if err := Apply(s, []review.Change{c}, box, Options{Yes: true, Branch: "agent", Out: &out}); err == nil || !strings.Contains(err.Error(), "leads to") {
		t.Fatalf("--branch went to a moved root: %v", err)
	}
	if gs, _ := listGenerations(s); len(gs) != 0 {
		t.Fatalf("a refused apply started %d undo journals", len(gs))
	}
	g, err := beginGeneration(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.apply(c); err == nil || !strings.Contains(err.Error(), "leads to") {
		t.Fatalf("the generation applied through a moved root: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, "new.txt")); err == nil {
		t.Fatal("the change landed where the link leads")
	}
}

// A rollback after the root moved restores nothing there.
func TestRollbackRefusesMovedRoot(t *testing.T) {
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	s := rootSession(t, ws)
	upper := filepath.Join(t.TempDir(), "new.txt")
	if err := os.WriteFile(upper, []byte("agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := review.Change{Layer: "ws", Rel: "new.txt", Path: filepath.Join(ws, "new.txt"), Upper: upper, Kind: review.Added, Mode: 0o644}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	var out bytes.Buffer
	if err := Apply(s, []review.Change{c}, box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err)
	}
	elsewhere := moveRoot(t, ws)
	theirs := filepath.Join(elsewhere, "new.txt")
	if err := os.WriteFile(theirs, []byte("theirs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Rollback(s, nil, &out); err == nil || !strings.Contains(err.Error(), "leads to") {
		t.Fatalf("rolled back through a moved root: %v", err)
	}
	if data, err := os.ReadFile(theirs); err != nil || string(data) != "theirs\n" {
		t.Fatalf("the rollback removed what the link leads to: %q %v", data, err)
	}
}

// A workspace named through a link from the start (/home leading to
// /var/home, say) applies as usual.
func TestApplyThroughLinkedRootFromTheStart(t *testing.T) {
	real := t.TempDir()
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.Symlink(real, ws); err != nil {
		t.Fatal(err)
	}
	s := rootSession(t, ws)
	upper := filepath.Join(t.TempDir(), "new.txt")
	if err := os.WriteFile(upper, []byte("agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := review.Change{Layer: "ws", Rel: "new.txt", Path: filepath.Join(ws, "new.txt"), Upper: upper, Kind: review.Added, Mode: 0o644}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	var out bytes.Buffer
	if err := Apply(s, []review.Change{c}, box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(real, "new.txt")); err != nil || string(data) != "agent\n" {
		t.Fatalf("not applied: %q %v", data, err)
	}
}

// A new directory made where the workspace was, after it was moved away,
// is not the session's workspace either.
func TestApplyRefusesReplacedRoot(t *testing.T) {
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	s := rootSession(t, ws)
	upper := filepath.Join(t.TempDir(), "new.txt")
	if err := os.WriteFile(upper, []byte("agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := review.Change{Layer: "ws", Rel: "new.txt", Path: filepath.Join(ws, "new.txt"), Upper: upper, Kind: review.Added, Mode: 0o644}
	if err := os.Rename(ws, ws+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	var out bytes.Buffer
	if err := Apply(s, []review.Change{c}, box, Options{Yes: true, Force: true, Out: &out}); err == nil || !strings.Contains(err.Error(), "another directory") {
		t.Fatalf("applied into a directory made in the workspace's place: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(ws, "new.txt")); err == nil {
		t.Fatal("the change landed in the new directory")
	}
}

// An apply that fails after the root moved rolls back nothing through it:
// the rollback checks every entry first.
func TestFailedApplyRollbackRefusesMovedRoot(t *testing.T) {
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	s := rootSession(t, ws)
	upper := filepath.Join(t.TempDir(), "new.txt")
	if err := os.WriteFile(upper, []byte("agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := review.Change{Layer: "ws", Rel: "new.txt", Path: filepath.Join(ws, "new.txt"), Upper: upper, Kind: review.Added, Mode: 0o644}
	g, err := beginGeneration(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.apply(c); err != nil {
		t.Fatal(err)
	}
	elsewhere := moveRoot(t, ws)
	theirs := filepath.Join(elsewhere, "new.txt")
	if err := os.WriteFile(theirs, []byte("theirs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if left, err := g.rollback(&out); err == nil || left != 1 || !strings.Contains(err.Error(), "leads to") {
		t.Fatalf("rolled back through a moved root: %d left, %v", left, err)
	}
	if data, err := os.ReadFile(theirs); err != nil || string(data) != "theirs\n" {
		t.Fatalf("the rollback removed what the link leads to: %q %v", data, err)
	}
}

// The root of a change is found by its layer, so a $HOME given with a
// trailing slash is checked like any other.
func TestApplyRefusesMovedHomeSpelledWithSlash(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: home + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if s.HomeID.Real == "" {
		t.Fatal("Create recorded no root for $HOME")
	}
	s.Status = session.StatusStopped
	upper := filepath.Join(t.TempDir(), ".profile")
	if err := os.WriteFile(upper, []byte("agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := review.Change{Layer: "home", Rel: ".profile", Path: filepath.Join(home, ".profile"), Upper: upper, Kind: review.Added, Mode: 0o644}
	elsewhere := moveRoot(t, home)
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	var out bytes.Buffer
	if err := Apply(s, []review.Change{c}, box, Options{Yes: true, Force: true, Out: &out}); err == nil || !strings.Contains(err.Error(), "leads to") {
		t.Fatalf("applied below a moved $HOME: %v", err)
	}
	g, err := beginGeneration(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.apply(c); err == nil || !strings.Contains(err.Error(), "leads to") {
		t.Fatalf("the generation applied below a moved $HOME: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, ".profile")); err == nil {
		t.Fatal("the change landed where the link leads")
	}
}

// A change whose path is not its layer's root joined with its Rel is
// refused once roots are recorded, and so is a layer the session has no
// root for.
func TestHeldNeedsTheLayersRoot(t *testing.T) {
	ws := t.TempDir()
	id, err := session.DirIDOf(ws)
	if err != nil {
		t.Fatal(err)
	}
	r := roots{"ws": root{ws, id}}
	if err := r.held("ws", filepath.Join(ws, "a/b"), "a/b"); err != nil {
		t.Fatal(err)
	}
	if err := r.held("ws", filepath.Join(t.TempDir(), "a/b"), "a/b"); err == nil {
		t.Fatal("a path outside the layer's root passed")
	}
	if err := r.held("etc", "/etc/x", "x"); err == nil {
		t.Fatal("a layer with no root passed")
	}
	if err := r.held("home", "/home/u/x", "x"); err != nil {
		t.Fatalf("an unrecorded $HOME is not checked, as in sessions from before: %v", err)
	}
}
