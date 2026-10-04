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
	Yes         bool     // do not ask
	Force       bool     // apply over files changed on the host during the session
	Interactive bool     // ask about each unit
	Only        []string // apply only units touching these paths
	// TrustGit runs the session's pushes although the session changed
	// .git/config or git hooks; hooks stay disabled.
	TrustGit bool
	In       io.Reader
	Out      io.Writer
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
		return runIntents(s, box, s.GitTouched, bufio.NewReader(o.In), o)
	}
	if s.Status == session.StatusRunning {
		return fmt.Errorf("session %s is still running", s.ID)
	}
	in := bufio.NewReader(o.In)
	chosen, err := choose(Units(cs), in, o)
	if err != nil {
		return err
	}
	var picked []review.Change
	for _, u := range chosen {
		picked = append(picked, u.Changes...)
	}
	if cf := Conflicts(s, picked); len(cf) > 0 && !o.Force {
		fmt.Fprintf(o.Out, "Conflicts: %d files changed on the host while the agent worked:\n", len(cf))
		for _, c := range cf {
			fmt.Fprintf(o.Out, "  %s: %s\n", c.Path, c.Reason)
		}
		return fmt.Errorf("nothing applied; rerun with --force to overwrite, or discard the session")
	}
	for _, c := range picked {
		if err := applyOne(c); err != nil {
			return fmt.Errorf("%s: %w (earlier changes are already applied)", c.Path, err)
		}
	}
	forget(picked)
	if gitTouched(picked) {
		s.GitTouched = true
	}
	if len(picked) > 0 {
		fmt.Fprintf(o.Out, "Applied %d changes.\n", len(picked))
	}

	rest, err := review.Scan(s)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		s.Status = session.StatusApplied
	} else {
		fmt.Fprintf(o.Out, "%d changes stay in session %s: airbag apply -i, or airbag discard.\n", len(rest), s.ID)
	}
	if err := s.Save(); err != nil {
		return err
	}
	for _, c := range rest {
		if c.Layer == "ws" && strings.HasPrefix(c.Rel, ".git/") {
			fmt.Fprintln(o.Out, "Intents wait: the session's git changes are not applied yet.")
			return nil
		}
	}
	return runIntents(s, box, s.GitTouched, in, o)
}

// choose picks the units to apply: all of them, the ones matching
// --only, or one by one.
func choose(units []Unit, in *bufio.Reader, o Options) ([]Unit, error) {
	if len(units) == 0 {
		return nil, nil
	}
	if len(o.Only) > 0 {
		var out []Unit
		for _, u := range units {
			if u.matches(o.Only) {
				out = append(out, u)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("no changes match %s", strings.Join(o.Only, " "))
		}
		return out, nil
	}
	if !o.Interactive {
		n := 0
		for _, u := range units {
			n += len(u.Changes)
			if len(u.Flags) > 0 && !o.Yes {
				fmt.Fprintf(o.Out, "  ! %-40s %s\n", u.Title, strings.Join(u.Flags, ", "))
			}
		}
		if !confirm(in, o, fmt.Sprintf("Apply %d changes to the real files?", n)) {
			return nil, fmt.Errorf("aborted, nothing applied")
		}
		return units, nil
	}
	var out []Unit
	for i := 0; i < len(units); i++ {
		u := units[i]
		flags := ""
		if len(u.Flags) > 0 {
			flags = "   ! " + strings.Join(u.Flags, ", ")
		}
		fmt.Fprintf(o.Out, "[%d/%d] %s%s\n", i+1, len(units), u.Title, flags)
		fmt.Fprint(o.Out, "  apply? [y]es [n]o [d]iff [a]ll remaining [q]uit: ")
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return out, nil
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			out = append(out, u)
		case "n", "no", "":
		case "d", "diff":
			for _, c := range u.Changes {
				review.Diff(o.Out, c)
			}
			i--
		case "a", "all":
			return append(out, units[i:]...), nil
		case "q", "quit":
			return out, nil
		default:
			i--
		}
	}
	return out, nil
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
		if it.Status == outbox.Running {
			// A run was recorded but not its end: airbag stopped mid-push.
			it.Status = outbox.Unknown
			it.Output = "airbag stopped while this ran, so it may or may not have reached the remote " +
				"(check with git ls-remote); it is not run again"
			if err := box.Update(it); err != nil {
				return fmt.Errorf("intent %s: %w", it.ID, err)
			}
			fmt.Fprintf(o.Out, "intent %s: %s\n", it.ID, it.Output)
			continue
		}
		if it.Status != outbox.Pending {
			continue
		}
		args, err := outbox.GitPush(it.Argv)
		if err != nil || !within(it.Cwd, s.Workspace) {
			it.Status, it.Output = outbox.Rejected, fmt.Sprintf("invalid intent: %v (cwd %s)", err, it.Cwd)
			fmt.Fprintf(o.Out, "intent %s rejected: %s\n", it.ID, it.Output)
			if err := box.Update(it); err != nil {
				return fmt.Errorf("intent %s: %w", it.ID, err)
			}
			continue
		}
		if risky {
			// The repository now carries the agent's git config or hooks,
			// which run on the host during a push (hooks, credential
			// helpers, ssh commands). Nothing runs until the user has
			// looked and says so; even then hooks stay off.
			if !o.TrustGit {
				fmt.Fprintf(o.Out, "intent %s left pending: session %s changed .git/config or git hooks, which run on this "+
					"machine during a push. Inspect them (git config --local --list; ls .git/hooks), then run "+
					"`airbag apply --trust-git %s`, or push yourself\n", it.ID, s.ID, s.ID)
				continue
			}
			args = append([]string{"-c", "core.hooksPath=/dev/null"}, args...)
		}
		where := pushTarget(it.Cwd, args)
		if !confirm(in, o, fmt.Sprintf("Run intent %s: `git %s` → %s?", it.ID, strings.Join(args, " "), where)) {
			it.Status = outbox.Rejected
			if err := box.Update(it); err != nil {
				return fmt.Errorf("intent %s: %w", it.ID, err)
			}
			continue
		}
		// Record the start first: if airbag stops during the push, the
		// next apply reports the outcome as unknown instead of pushing
		// again.
		it.Status = outbox.Running
		if err := box.Update(it); err != nil {
			return fmt.Errorf("intent %s not run: %w", it.ID, err)
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
		if err := box.Update(it); err != nil {
			return fmt.Errorf("intent %s ran (%s), but its result was not recorded: %w", it.ID, it.Status, err)
		}
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
