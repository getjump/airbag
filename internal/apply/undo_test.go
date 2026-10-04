package apply

import (
	"bytes"
	"encoding/json"
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
	t.Cleanup(func() { box.Close() })
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
	t.Cleanup(func() { box.Close() })
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

// Only a temp file named as copyFile names them, in a directory the
// apply copied a file into, counts as the apply's; a user's file with a
// similar name keeps the directory as it is.
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
	defer box.Close()
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
