// Package apply commits a reviewed branch to the real world: first the
// file changes, then the intents from the outbox.
package apply

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/review"
	"github.com/getjump/airbag/internal/session"
)

type Options struct {
	Yes   bool // do not ask
	Force bool // apply over files changed on the host during the session
	In    io.Reader
	Out   io.Writer
}

type Conflict struct {
	Path   string
	Reason string
}

// Conflicts lists real files that changed after the session started.
// Overlay reads the live workspace, so the agent's version was based
// on the old file; applying it would silently drop the human's edit.
func Conflicts(s *session.Session, cs []review.Change) []Conflict {
	var out []Conflict
	for _, c := range cs {
		st, err := os.Lstat(c.Path)
		exists := err == nil
		switch c.Kind {
		case review.Added:
			if exists && !(c.IsDir() && st.IsDir()) {
				out = append(out, Conflict{c.Path, "created on the host during the session"})
			}
		default:
			if !exists {
				if c.Kind != review.Deleted {
					out = append(out, Conflict{c.Path, "deleted on the host during the session"})
				}
				continue
			}
			if st.IsDir() && (c.Kind == review.Deleted || c.Kind == review.Replaced) {
				if p := changedInside(c.Path, s.Created); p != "" {
					out = append(out, Conflict{p, "changed on the host during the session, inside a directory the agent removed"})
				}
			} else if !st.IsDir() && changedAfter(c.Path, s.Created) {
				out = append(out, Conflict{c.Path, "changed on the host during the session"})
			}
		}
	}
	return out
}

func changedAfter(p string, t time.Time) bool {
	var st unix.Stat_t
	if unix.Lstat(p, &st) != nil {
		return false
	}
	return time.Unix(st.Ctim.Sec, st.Ctim.Nsec).After(t)
}

func changedInside(dir string, t time.Time) string {
	found := ""
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found != "" {
			return filepath.SkipAll
		}
		if !d.IsDir() && changedAfter(p, t) {
			found = p
		}
		return nil
	})
	return found
}

func Apply(s *session.Session, cs []review.Change, box *outbox.Box, o Options) error {
	if s.Status == session.StatusApplied {
		return runIntents(s, box, false, bufio.NewReader(o.In), o)
	}
	if s.Status == session.StatusRunning {
		return fmt.Errorf("session %s is still running", s.ID)
	}
	if cf := Conflicts(s, cs); len(cf) > 0 && !o.Force {
		fmt.Fprintf(o.Out, "Conflicts: %d files changed on the host while the agent worked:\n", len(cf))
		for _, c := range cf {
			fmt.Fprintf(o.Out, "  %s: %s\n", c.Path, c.Reason)
		}
		return fmt.Errorf("nothing applied; rerun with --force to overwrite, or discard the session")
	}
	in := bufio.NewReader(o.In)
	if len(cs) > 0 {
		if att := review.Attention(cs); len(att) > 0 {
			fmt.Fprintln(o.Out, "Attention:")
			for _, c := range att {
				fmt.Fprintf(o.Out, "  ! %s  %s\n", c.Path, strings.Join(c.Flags, ", "))
			}
		}
		if !confirm(in, o, fmt.Sprintf("Apply %d changes to the real files?", len(cs))) {
			return fmt.Errorf("aborted, nothing applied")
		}
		for _, c := range cs {
			if err := applyOne(c); err != nil {
				return fmt.Errorf("%s: %w (earlier changes are already applied)", c.Path, err)
			}
		}
		fmt.Fprintf(o.Out, "Applied %d changes.\n", len(cs))
	}

	s.Status = session.StatusApplied
	if err := s.Save(); err != nil {
		return err
	}
	return runIntents(s, box, gitTouched(cs), in, o)
}

// gitTouched reports whether the branch changed git config or hooks:
// those can redirect a push or run code on the host during it.
func gitTouched(cs []review.Change) bool {
	for _, c := range cs {
		if c.Layer == "ws" && (c.Rel == ".git/config" || strings.HasPrefix(c.Rel, ".git/hooks/")) {
			return true
		}
	}
	return false
}

func runIntents(s *session.Session, box *outbox.Box, risky bool, in *bufio.Reader, o Options) error {
	intents, err := box.List()
	if err != nil {
		return err
	}
	for _, it := range intents {
		if it.Status != outbox.Pending {
			continue
		}
		args, err := outbox.GitPush(it.Argv)
		if err != nil || !within(it.Cwd, s.Workspace) {
			it.Status, it.Output = outbox.Rejected, fmt.Sprintf("invalid intent: %v (cwd %s)", err, it.Cwd)
			fmt.Fprintf(o.Out, "intent %s rejected: %s\n", it.ID, it.Output)
			_ = box.Update(it)
			continue
		}
		if risky {
			// The agent's hooks never run on the host.
			args = append([]string{"-c", "core.hooksPath=/dev/null"}, args...)
		}
		where := pushTarget(it.Cwd, args)
		if risky && o.Yes {
			fmt.Fprintf(o.Out, "intent %s left pending: the session changed .git/config or git hooks; "+
				"check the push target (%s) and run `airbag apply %s` without --yes\n", it.ID, where, s.ID)
			continue
		}
		if !confirm(in, o, fmt.Sprintf("Run intent %s: `git %s` → %s?", it.ID, strings.Join(args, " "), where)) {
			it.Status = outbox.Rejected
			_ = box.Update(it)
			continue
		}
		cmd := exec.Command("git", args...)
		cmd.Dir = it.Cwd
		outb, err := cmd.CombinedOutput()
		_, _ = o.Out.Write(outb)
		it.Output = string(outb)
		it.Status = outbox.Done
		if err != nil {
			it.Status = outbox.Failed
			fmt.Fprintf(o.Out, "intent %s failed: %v\n", it.ID, err)
		}
		_ = box.Update(it)
	}
	return nil
}

// pushTarget resolves where a push really goes, after the branch's
// .git/config has been applied.
func pushTarget(cwd string, args []string) string {
	remote := "origin"
	for _, a := range args[1:] {
		if !strings.HasPrefix(a, "-") && a != "core.hooksPath=/dev/null" && a != "push" {
			remote = a
			break
		}
	}
	out, err := exec.Command("git", "-C", cwd, "remote", "get-url", "--push", remote).Output()
	if err != nil {
		return remote
	}
	return strings.TrimSpace(string(out))
}

func within(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

func confirm(in *bufio.Reader, o Options, q string) bool {
	if o.Yes {
		return true
	}
	fmt.Fprintf(o.Out, "%s [y/N] ", q)
	line, _ := in.ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y")
}

func applyOne(c review.Change) error {
	switch c.Kind {
	case review.Deleted:
		return os.RemoveAll(c.Path)
	case review.Replaced:
		if err := os.RemoveAll(c.Path); err != nil {
			return err
		}
		return os.MkdirAll(c.Path, c.Mode)
	}
	switch c.Type {
	case fs.ModeDir:
		if err := os.MkdirAll(c.Path, c.Mode); err != nil {
			return err
		}
		return os.Chmod(c.Path, c.Mode)
	case fs.ModeSymlink:
		target, err := os.Readlink(c.Upper)
		if err != nil {
			return err
		}
		_ = os.Remove(c.Path)
		return os.Symlink(target, c.Path)
	default:
		return copyFile(c.Upper, c.Path, c.Mode)
	}
}

// copyFile replaces dst atomically: write a temp file next to it, then
// rename over the old one.
func copyFile(src, dst string, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".airbag-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if st, err := os.Lstat(dst); err == nil && st.IsDir() {
		if err := os.RemoveAll(dst); err != nil {
			return err
		}
	}
	return os.Rename(tmp.Name(), dst)
}
