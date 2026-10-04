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
//     so is a replaced directory that holds anything the rollback did
//     not take out; their previous versions stay in the generation.

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
	Clone    bool      `json:"clone,omitempty"` // the branch is a full copy, not an upper layer
	Session  string    `json:"session"`
	Started  time.Time `json:"started"`
	Complete bool      `json:"complete"`
	// Partial: rolled back except Entries, which were left as they were;
	// their previous versions are kept under saved/.
	Partial bool       `json:"partial,omitempty"`
	Entries []genEntry `json:"entries"`
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
	g := &generation{dir: filepath.Join(root, strconv.Itoa(n)), Session: s.ID, Started: time.Now(), Clone: s.Clone}
	if err := os.MkdirAll(filepath.Join(g.dir, "saved"), 0o700); err != nil {
		return nil, err
	}
	return g, g.save()
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
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
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

// rollback undoes the generation's entries, last first. Each real path
// that still looks as the apply left it gets its previous version back,
// and the agent's version returns to the session. It reports the paths
// it had to leave.
func (g *generation) rollback(out io.Writer) (left int, err error) {
	var dirs []string // directories the apply created, removed last, deepest first
	var kept []genEntry
	keep := func(e genEntry, why string) {
		fmt.Fprintf(out, "  left as is (%s): %s\n", why, e.Path)
		if _, err := os.Lstat(e.Saved); e.Saved != "" && err == nil {
			fmt.Fprintf(out, "    its version from before the apply is kept at %s\n", e.Saved)
		}
		kept = append(kept, e)
		left++
	}
	for i := len(g.Entries) - 1; i >= 0; i-- {
		e := g.Entries[i]
		dirs = append(dirs, e.Made...)
		_, serr := os.Lstat(e.Saved)
		moved := e.Saved != "" && serr == nil
		if e.After == "" {
			// The step did not finish. If the previous version never
			// left its place, there is nothing to undo here.
			if e.Saved != "" && !moved {
				continue
			}
		} else if fingerprint(e.Path) != e.After {
			keep(e, "changed after the apply")
			continue
		}
		// A replaced directory goes only once it is empty: by now the
		// entries inside it that the apply made are gone, and so are
		// the directories it made there that nothing is left in, so
		// whatever is left was added or kept after the apply, and is
		// not ours to remove.
		if e.Type == fs.ModeDir && e.Saved != "" {
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
			if err := giveBack(e, g.Clone); err != nil {
				return left, fmt.Errorf("%s: return the agent's version to the session: %w", e.Path, err)
			}
		}
		if e.Kind == review.Added && e.Type == fs.ModeDir && e.Saved == "" {
			dirs = append(dirs, e.Path)
			continue
		}
		// What is at the path now is the agent's (or half of it, or
		// nothing for a deletion); the user's version was moved away.
		if err := os.RemoveAll(e.Path); err != nil && !gone(err) {
			return left, err
		}
		if moved {
			if err := move(e.Saved, e.Path); err != nil {
				return left, fmt.Errorf("%s: restore: %w", e.Path, err)
			}
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, d := range dirs {
		removeEmptyDir(d)
	}
	if len(kept) == 0 {
		return left, os.RemoveAll(g.dir)
	}
	// Keep what was left, with its previous versions, so nothing from
	// before the apply is lost and a later rollback can try again.
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	g.Entries, g.Complete, g.Partial = kept, true, true
	return left, g.save()
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
		return nil // still there: the change was never forgotten
	}
	if clone && e.Kind == review.Deleted {
		return nil // absent from the clone is what a deletion is
	}
	if err := os.MkdirAll(filepath.Dir(e.Upper), 0o755); err != nil {
		return err
	}
	switch {
	case e.Kind == review.Deleted:
		// overlayfs's whiteout: a 0:0 character device (unprivileged
		// since Linux 5.8).
		return unix.Mknod(e.Upper, syscall.S_IFCHR|0o000, 0)
	case e.Type == fs.ModeDir:
		if err := os.MkdirAll(e.Upper, 0o755); err != nil {
			return err
		}
		if e.Kind == review.Replaced {
			// Opaque again: the directory replaces the real one.
			_ = unix.Setxattr(e.Upper, "user.overlay.opaque", []byte("y"), 0)
		}
		return nil
	default:
		return copyTree(e.Path, e.Upper)
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
	defer f.Close()
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
			return os.Symlink(t, dst)
		case info.Mode().IsRegular():
			return copyFile(p, dst, info.Mode().Perm())
		}
		return nil // sockets, devices: nothing to keep
	})
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
