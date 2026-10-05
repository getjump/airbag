package apply

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/review"
	"github.com/getjump/airbag/internal/session"
)

// Every apply is a generation: before a real file changes, what was
// there moves into the session, and the journal records it and, after
// the change, what was put there. The journal is written before each
// step, so a failure or a crash halfway can be undone.
//
//   - apply rolls back by itself when a step fails, so it either
//     applies everything it picked or nothing;
//   - `airbag rollback` undoes the last generation: the user's versions
//     come back and the agent's go back into the session, to apply again
//     or discard. A file changed after the apply is left as it is, and
//     so is a replaced directory that holds anything the apply did not
//     put there, whole, with what the apply put inside it; their
//     previous versions stay in the generation.

type genEntry struct {
	Layer string      `json:"layer"`
	Rel   string      `json:"rel"`
	Path  string      `json:"path"`  // the real file
	Upper string      `json:"upper"` // where the agent's version lives in the session
	Kind  string      `json:"kind"`
	Type  fs.FileMode `json:"type"`
	Saved string      `json:"saved,omitempty"` // the previous version, "" when there was none
	After string      `json:"after,omitempty"` // fingerprint once applied; "" while in progress
	// Made: parent directories the step had to create. A replaced
	// directory that a rollback left also keeps here the directories
	// the apply made inside it that were still there.
	Made []string `json:"made,omitempty"`
}

type generation struct {
	dir      string
	roots    roots     // checked before each change; not kept in the journal
	Clone    bool      `json:"clone,omitempty"` // the branch is a full copy, not an upper layer
	Session  string    `json:"session"`
	Started  time.Time `json:"started"`
	Complete bool      `json:"complete"`
	// Partial: rolled back except Entries, which were left as they were;
	// their previous versions are kept under saved/.
	Partial bool `json:"partial,omitempty"`
	// Stopped: a rollback stopped part way, a root having changed;
	// Entries are what it had not reached and what it kept, and the next
	// rollback finishes it as this one would have.
	Stopped bool       `json:"stopped,omitempty"`
	Entries []genEntry `json:"entries"`
	// Dirs: directories the apply made that a partial rollback could
	// not remove because they were not empty; the next one tries again.
	Dirs []string `json:"dirs,omitempty"`
}

func generationsDir(s *session.Session) string { return filepath.Join(s.Dir, "undo") }

func beginGeneration(s *session.Session) (*generation, error) {
	root := generationsDir(s)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	n := 1
	if gs, _ := listGenerations(s); len(gs) > 0 {
		n = gs[len(gs)-1].n + 1
	}
	g := &generation{dir: filepath.Join(root, strconv.Itoa(n)), roots: rootsOf(s), Session: s.ID, Started: time.Now(), Clone: s.Clone}
	if err := os.MkdirAll(filepath.Join(g.dir, "saved"), 0o700); err != nil {
		return nil, err
	}
	if err := g.save(); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *generation) save() error {
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(g.dir, "journal.json.tmp")
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(g.dir, "journal.json"))
}

type genRef struct {
	n   int
	dir string
}

func listGenerations(s *session.Session) ([]genRef, error) {
	es, err := os.ReadDir(generationsDir(s))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []genRef
	for _, e := range es {
		if n, err := strconv.Atoi(e.Name()); err == nil && e.IsDir() {
			out = append(out, genRef{n, filepath.Join(generationsDir(s), e.Name())})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].n < out[j].n })
	return out, nil
}

func loadGeneration(dir string) (*generation, error) {
	b, err := os.ReadFile(filepath.Join(dir, "journal.json"))
	if err != nil {
		return nil, err
	}
	g := &generation{dir: dir}
	return g, json.Unmarshal(b, g)
}

// interrupted returns an apply of s that did not finish, if any.
func interrupted(s *session.Session) *generation {
	gs, _ := listGenerations(s)
	if len(gs) == 0 {
		return nil
	}
	g, err := loadGeneration(gs[len(gs)-1].dir)
	if err != nil || g.Complete {
		return nil
	}
	return g
}

// apply changes one real path, journal first.
func (g *generation) apply(c review.Change) error {
	// Checked before the previous version is moved, and again in
	// applyOne for its own callers.
	if err := g.roots.held(c.Layer, c.Path, c.Rel); err != nil {
		return err
	}
	if err := parentsUnlinked(c, nil); err != nil {
		return err
	}
	e := genEntry{Layer: c.Layer, Rel: c.Rel, Path: c.Path, Upper: c.Upper, Kind: c.Kind, Type: c.Type}
	for d := filepath.Dir(c.Path); ; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); err == nil || d == filepath.Dir(d) {
			break
		}
		e.Made = append(e.Made, d)
	}
	if _, err := os.Lstat(c.Path); err == nil && !(c.IsDir() && c.Kind == review.Added) {
		e.Saved = filepath.Join(g.dir, "saved", strconv.Itoa(len(g.Entries)))
	}
	g.Entries = append(g.Entries, e)
	if err := g.save(); err != nil {
		return err
	}
	if e.Saved != "" {
		if err := move(c.Path, e.Saved); err != nil {
			return fmt.Errorf("keep the previous version: %w", err)
		}
	}
	if err := applyOne(c); err != nil {
		return err
	}
	g.Entries[len(g.Entries)-1].After = fingerprint(c.Path)
	return g.save()
}

func (g *generation) finish() error {
	g.Complete = true
	return g.save()
}

// afterRemove is a test hook, called once a rollback entry has removed
// the agent's version and before it restores the previous one; nil
// outside tests.
var afterRemove func(path string)

// rollback undoes the generation's entries, last first. Each real path
// that still looks as the apply left it gets its previous version back,
// and the agent's version returns to the session. It reports the paths
// it had to leave.
func (g *generation) rollback(out io.Writer) (left int, err error) {
	// Through a root that is another directory now, the rollback would
	// remove and restore there. Every entry is checked before anything
	// moves, when an apply that failed rolls itself back too.
	for _, e := range g.Entries {
		if err := g.roots.held(e.Layer, e.Path, e.Rel); err != nil {
			return len(g.Entries), fmt.Errorf("nothing rolled back: %w; put the directory back, then roll back: your versions from before the apply are kept in %s", err, filepath.Join(g.dir, "saved"))
		}
	}
	dirs := slices.Clone(g.Dirs) // directories the apply created, removed last, deepest first
	var kept []genEntry
	keep := func(e genEntry, why string) {
		if why != "" {
			fmt.Fprintf(out, "  left as is (%s): %s\n", why, e.Path)
			if _, err := os.Lstat(e.Saved); e.Saved != "" && err == nil {
				fmt.Fprintf(out, "    its version from before the apply is kept at %s\n", e.Saved)
			}
		}
		kept = append(kept, e)
		left++
	}
	// Which replaced directories stay is decided before anything inside
	// them is touched. Rolling back only what the apply put inside one
	// that also holds something else would leave the user with neither
	// version: not the agent's, and not their own, which is in saved/.
	whole := g.leftWhole()
	inWhole := func(p string) string {
		for d := range whole {
			if p != d && within(p, d) {
				return d
			}
		}
		return ""
	}
	inside := map[string]int{} // paths left inside each of those directories
	// The root can change while the rollback runs (while leftWhole walks
	// a large directory, say), so each entry is checked again before it
	// moves anything, and the roots before each directory goes. Stopped
	// there, what is not rolled back yet stays in the journal: the
	// entries not reached, those kept, and the directories to remove.
	stop := func(i int, err error) (int, error) {
		rest := slices.Clone(g.Entries[:i+1])
		for j := len(kept) - 1; j >= 0; j-- {
			rest = append(rest, kept[j])
		}
		slices.Sort(dirs)
		g.Entries, g.Dirs, g.Stopped = rest, slices.Compact(dirs), true
		if serr := g.save(); serr != nil {
			err = errors.Join(err, serr)
		}
		return len(rest), fmt.Errorf("rollback stopped: %w; put the directory back, then roll back again: what is not rolled back yet stays in the journal, your versions from before the apply in %s", err, filepath.Join(g.dir, "saved"))
	}
	for i := len(g.Entries) - 1; i >= 0; i-- {
		e := g.Entries[i]
		if err := g.roots.held(e.Layer, e.Path, e.Rel); err != nil {
			return stop(i, err)
		}
		if d := inWhole(e.Path); d != "" {
			switch {
			case !ours(e):
				keep(e, "changed after the apply")
			case e.Saved != "":
				keep(e, "inside a directory left as is")
			default:
				keep(e, "") // counted in the line for d
				inside[d]++
			}
			continue
		}
		dirs = append(dirs, e.Made...)
		_, serr := os.Lstat(e.Saved)
		moved := e.Saved != "" && serr == nil
		if e.After == "" {
			// The step did not finish. If the previous version never
			// left its place, there is nothing to undo here.
			if e.Saved != "" && !moved {
				continue
			}
			// Otherwise the path holds nothing yet or the agent's
			// version; anything else was put there since, and stays.
			if !ours(e) {
				keep(e, "changed after the apply stopped")
				continue
			}
		} else if fp := fingerprint(e.Path); fp != e.After {
			if fp == "absent" && e.Saved == "" {
				// The user removed the agent's version, and nothing was
				// there before the apply: there is nothing to undo, and
				// nothing to keep. Kept, the entry could later take for
				// the agent's a file of the user's that is the same.
				continue
			}
			keep(e, "changed after the apply")
			continue
		}
		if whole[e.Path] {
			keep(e, "holds files added or changed after the apply")
			if n := inside[e.Path]; n > 0 {
				fmt.Fprintf(out, "    so is what the apply put inside it (paths: %d)\n", n)
			}
			continue
		}
		// Any other replaced directory held only what the apply put
		// there, and it goes once that is out: by now the entries inside
		// it are gone, and so are the directories the apply made there.
		// Whatever is still left was added while the rollback ran, and
		// is not ours to remove.
		// Each write below is checked again right before it: fingerprint
		// and leftWhole can take long on a large file or directory.
		held := func() error { return g.roots.held(e.Layer, e.Path, e.Rel) }
		if e.Type == fs.ModeDir && e.Saved != "" {
			if err := held(); err != nil {
				return stop(i, err)
			}
			if moved {
				// Checked by leftWhole: its temp files are the apply's.
				removeTemps(e.Path, g.copyingTo())
			}
			var still []string
			dirs, still = removeInside(dirs, e.Path)
			if !emptyOrAbsent(e.Path) {
				// The directories the apply made here that still hold
				// something stay in the journal with this entry, so a
				// later rollback can remove them once they are empty
				// and then restore the directory.
				for _, d := range still {
					if !slices.Contains(e.Made, d) {
						e.Made = append(e.Made, d)
					}
				}
				keep(e, "holds files added or changed after the apply")
				continue
			}
		}
		if e.After != "" {
			if err := held(); err != nil {
				return stop(i, err)
			}
			if err := giveBack(e, g.Clone); err != nil {
				return left, fmt.Errorf("%s: return the agent's version to the session: %w", e.Path, err)
			}
		}
		// A directory with nothing before it, added or replacing what was
		// gone by the time of the apply, is one the apply made: it goes
		// with them, only once it is empty.
		if e.Type == fs.ModeDir && e.Saved == "" {
			dirs = append(dirs, e.Path)
			continue
		}
		// What is at the path now is the agent's (or half of it, or
		// nothing for a deletion); the user's version was moved away.
		if err := held(); err != nil {
			return stop(i, err)
		}
		if err := os.RemoveAll(e.Path); err != nil && !gone(err) {
			return left, err
		}
		if afterRemove != nil {
			afterRemove(e.Path)
		}
		if moved {
			if err := held(); err != nil {
				// The agent's version is out and back in the session:
				// to the next rollback this is a step that did not
				// finish, whose previous version saved/ holds.
				g.Entries[i].After = ""
				return stop(i, err)
			}
			if err := move(e.Saved, e.Path); err != nil {
				return left, fmt.Errorf("%s: restore: %w", e.Path, err)
			}
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	var still []string
	for _, d := range dirs {
		if err := g.roots.all(); err != nil {
			return stop(-1, err)
		}
		if inWhole(d) == "" {
			removeEmptyDir(d)
		}
		if _, err := os.Lstat(d); err == nil && !slices.Contains(still, d) {
			still = append(still, d)
		}
	}
	if len(kept) == 0 {
		// Nothing else is left, so what keeps those directories there
		// is the user's, and there is no later rollback to try again.
		return left, os.RemoveAll(g.dir)
	}
	// Keep what was left, with its previous versions, so nothing from
	// before the apply is lost and a later rollback can try again.
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	g.Entries, g.Dirs, g.Complete, g.Partial, g.Stopped = kept, still, true, true, false
	return left, g.save()
}

// leftWhole returns the replaced directories, their previous versions
// moved into saved/, that hold anything the apply did not put there.
func (g *generation) leftWhole() map[string]bool {
	entries := map[string]genEntry{}
	made, copying := map[string]bool{}, g.copyingTo()
	for _, d := range g.Dirs {
		made[d] = true
	}
	for _, e := range g.Entries {
		entries[e.Path] = e
		for _, d := range e.Made {
			made[d] = true
		}
	}
	whole := map[string]bool{}
	for _, e := range g.Entries {
		if e.Kind != review.Replaced || e.Saved == "" || fingerprint(e.Path) != "dir" {
			continue
		}
		if _, err := os.Lstat(e.Saved); err == nil && !onlyApplied(e.Path, entries, made, copying) {
			whole[e.Path] = true
		}
	}
	return whole
}

// onlyApplied reports whether all there is under dir is what the apply
// put there: its entries as it left them, directories it made, and temp
// files it left when it was stopped.
func onlyApplied(dir string, entries map[string]genEntry, made, copying map[string]bool) bool {
	clean := true
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && p == dir {
			return nil
		}
		if err == nil {
			if e, ok := entries[p]; ok && ours(e) {
				return nil // a directory of the apply's is walked too
			}
			if d.IsDir() && made[p] || applyTemp(p, d, copying) {
				return nil
			}
		}
		clean = false
		return filepath.SkipAll
	})
	return clean
}

// copyingTo returns the directories of the copy steps that did not
// finish: only there can the apply have left a temp file. A step that
// finished renamed its temp file into place.
func (g *generation) copyingTo() map[string]bool {
	copying := map[string]bool{}
	for _, e := range g.Entries {
		if e.After == "" && e.Type == 0 && e.Kind != review.Deleted {
			copying[filepath.Dir(e.Path)] = true
		}
	}
	return copying
}

// applyTemp: p is a temp file copyFile was writing when the apply was
// stopped: a file named as os.CreateTemp names ".airbag-*", in the
// directory of a copy step that did not finish.
func applyTemp(p string, d fs.DirEntry, copying map[string]bool) bool {
	n, ok := strings.CutPrefix(d.Name(), ".airbag-")
	if !ok || n == "" || !d.Type().IsRegular() || !copying[filepath.Dir(p)] {
		return false
	}
	for _, c := range n {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// removeTemps removes the temp files under dir that an apply which was
// stopped left there.
func removeTemps(dir string, copying map[string]bool) {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && applyTemp(p, d, copying) {
			_ = os.Remove(p) //nolint:gosec // the rollback runs after the session stopped: nothing from the sandbox can swap a path during the walk
		}
		return nil
	})
}

// ours: the real path of e is as the apply left it. For a step that
// did not finish, that is nothing yet or the agent's version.
func ours(e genEntry) bool {
	fp := fingerprint(e.Path)
	if e.After == "" {
		return fp == "absent" || fp == agents(e)
	}
	return fp == e.After
}

// agents returns the fingerprint of the agent's version of e, as the
// step puts it at the real path.
func agents(e genEntry) string {
	if e.Kind == review.Deleted {
		return "absent" // and the session's whiteout is no file to read
	}
	return fingerprint(e.Upper)
}

// removeInside removes the directories of dirs that lie inside dir,
// deepest first. It returns the others, and those inside dir that are
// still there, such as one the user put a file in.
func removeInside(dirs []string, dir string) (rest, still []string) {
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	rest = dirs[:0]
	for _, d := range dirs {
		if d != dir && within(d, dir) {
			removeEmptyDir(d)
			if _, err := os.Lstat(d); err == nil {
				still = append(still, d)
			}
			continue
		}
		rest = append(rest, d)
	}
	return rest, still
}

// removeEmptyDir removes d only if it is an empty directory. Unlike
// os.Remove, rmdir never unlinks a file: d is left as it is when it
// holds something (ENOTEMPTY), when it is a file the user put in its
// place (ENOTDIR), when it is gone (ENOENT), and on any other failure.
func removeEmptyDir(d string) {
	_ = unix.Rmdir(d)
}

// emptyOrAbsent: nothing at p, or an empty directory.
func emptyOrAbsent(p string) bool {
	st, err := os.Lstat(p)
	if err != nil {
		return true
	}
	if !st.IsDir() {
		return false
	}
	es, err := os.ReadDir(p)
	return err == nil && len(es) == 0
}

// gone: the path is not there, or a parent is not a directory.
func gone(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// giveBack puts the agent's version of an applied path back into the
// session's upper layer: the file itself, or a whiteout for a deletion.
func giveBack(e genEntry, clone bool) error {
	if _, err := os.Lstat(e.Upper); err == nil {
		// Still there: the change was never forgotten, or, for a
		// replaced directory, a path inside it given back first made
		// it, without the mark.
		if !clone && e.Type == fs.ModeDir && e.Kind == review.Replaced {
			markOpaque(e.Upper)
		}
		return nil
	}
	if clone && e.Kind == review.Deleted {
		return nil // absent from the clone is what a deletion is
	}
	if err := os.MkdirAll(filepath.Dir(e.Upper), 0o755); err != nil { //nolint:gosec // a directory of the session's upper layer, inside the 0700 session dir
		return err
	}
	switch {
	case e.Kind == review.Deleted:
		// overlayfs's whiteout: a 0:0 character device (unprivileged
		// since Linux 5.8).
		return unix.Mknod(e.Upper, syscall.S_IFCHR, 0)
	case e.Type == fs.ModeDir:
		if err := os.MkdirAll(e.Upper, 0o755); err != nil { //nolint:gosec // a directory of the session's upper layer, inside the 0700 session dir
			return err
		}
		if e.Kind == review.Replaced {
			markOpaque(e.Upper)
		}
		return nil
	default:
		return copyTree(e.Path, e.Upper)
	}
}

// markOpaque makes dir opaque again: the directory replaces the real
// one, and the session shows none of what the real one holds.
func markOpaque(dir string) {
	_ = unix.Setxattr(dir, "user.overlay.opaque", []byte("y"), 0)
}

// clearOpaque makes dir an ordinary directory of the upper layer: what
// it replaced is the host's now, and the next scan must not take it for
// a replacement again.
func clearOpaque(dir string) {
	for _, attr := range []string{"user.overlay.opaque", "trusted.overlay.opaque"} {
		_ = unix.Removexattr(dir, attr)
	}
}

// fingerprint describes what is at p: absent, a directory, a symlink
// target, or a file's mode and content hash.
func fingerprint(p string) string {
	st, err := os.Lstat(p)
	switch {
	case err != nil:
		return "absent"
	case st.IsDir():
		return "dir"
	case st.Mode()&fs.ModeSymlink != 0:
		t, _ := os.Readlink(p)
		return "link:" + t
	}
	f, err := os.Open(p)
	if err != nil {
		return "unreadable"
	}
	defer func() { _ = f.Close() }() // read only
	h := sha256.New()
	_, _ = io.Copy(h, f)
	return fmt.Sprintf("file:%o:%s", st.Mode().Perm(), hex.EncodeToString(h.Sum(nil)))
}

// move renames, and copies then removes across filesystems.
func move(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return err
	}
	err := os.Rename(from, to)
	if err == nil || !errors.Is(err, syscall.EXDEV) {
		return err
	}
	if err := copyTree(from, to); err != nil {
		return err
	}
	return os.RemoveAll(from)
}

// copyTree copies a file, symlink or directory tree, keeping modes.
func copyTree(from, to string) error {
	return filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(dst, info.Mode().Perm())
		case info.Mode()&fs.ModeSymlink != 0:
			t, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(t, dst) //nolint:gosec // copies run after the session stopped: nothing from the sandbox can swap a path during the walk
		case info.Mode().IsRegular():
			return copyFile(p, dst, info.Mode().Perm())
		}
		return nil // sockets, devices: nothing to keep
	})
}

// Held is the user's version of Path from before an apply, which only
// the session has, at Saved.
type Held struct{ Path, Saved string }

// HeldVersions lists the versions from before an apply that s holds for
// paths a rollback left as they were, or that an apply which did not
// finish had moved. Discarding s would delete them.
func HeldVersions(s *session.Session) ([]Held, error) {
	gs, err := listGenerations(s)
	if err != nil {
		return nil, err
	}
	var out []Held
	for _, r := range gs {
		g, err := loadGeneration(r.dir)
		if err != nil {
			return nil, err
		}
		if g.Complete && !g.Partial && !g.Stopped {
			continue // applied: discarding it keeps the apply, as asked
		}
		for _, e := range g.Entries {
			if _, err := os.Lstat(e.Saved); e.Saved != "" && err == nil {
				out = append(out, Held{e.Path, e.Saved})
			}
		}
	}
	return out, nil
}

// Rollback undoes the last apply of s: real files get their previous
// versions back, the agent's versions return to the session. A pushed
// intent is not undone; Rollback lists those.
func Rollback(s *session.Session, done []string, out io.Writer) error {
	gs, err := listGenerations(s)
	if err != nil {
		return err
	}
	if len(gs) == 0 {
		if s.Branch != "" {
			return fmt.Errorf("session %s went to branch %s; delete it with git branch -D %s", s.ID, s.Branch, s.Branch)
		}
		return fmt.Errorf("session %s has no apply to roll back", s.ID)
	}
	g, err := loadGeneration(gs[len(gs)-1].dir)
	if err != nil {
		return err
	}
	g.roots = rootsOf(s)
	n, partial := len(g.Entries), g.Partial
	left, err := g.rollback(out)
	if err != nil {
		return err
	}
	if partial {
		fmt.Fprintf(out, "Session %s: %d of the paths left by the last rollback are rolled back now; %d stay as they are.\n", s.ID, n-left, left)
		return nil
	}
	if s.Status == session.StatusApplied {
		s.Status = session.StatusStopped
	}
	s.Baseline = time.Now()
	if err := s.Save(); err != nil {
		return err
	}
	fmt.Fprintf(out, "Rolled back %d changes of session %s; they are back in the session (airbag review).\n", n-left, s.ID)
	if left > 0 {
		fmt.Fprintf(out, "%d left as they are; their versions from before the apply stay in the session until it is discarded.\n", left)
	}
	for _, d := range done {
		fmt.Fprintf(out, "  not undone: %s\n", d)
	}
	return nil
}
