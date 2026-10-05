// Package apply commits a reviewed branch to the real world: first the
// file changes, then the intents from the outbox.
package apply

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/operation"
	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/review"
	"github.com/getjump/airbag/internal/secretfs"
	"github.com/getjump/airbag/internal/session"
)

type Options struct {
	Yes         bool     // do not ask
	Force       bool     // apply over files changed on the host during the session
	Interactive bool     // ask about each unit
	Only        []string // apply only units touching these paths
	Branch      string   // put the workspace result on this new branch instead
	// TrustGit runs the session's pushes although the session changed
	// .git/config or git hooks; hooks stay disabled.
	TrustGit bool
	// TrustLinks runs the session's deferred commands although links it
	// put in the files lead out of the workspace (linksOut).
	TrustLinks bool
	In         io.Reader
	Out        io.Writer
}

type Conflict struct {
	Path   string
	Reason string
}

// Conflicts lists real files that changed after the session started.
// Overlay reads the live workspace, so the agent's version was based
// on the old file; applying it would silently drop the human's edit.
func Conflicts(s *session.Session, cs []review.Change) []Conflict {
	base := s.Created
	if !s.Baseline.IsZero() {
		base = s.Baseline
	}
	// since is when p last matched the branch's view: the session's
	// start, or a later apply that wrote p or a directory above it.
	since := func(p string) time.Time {
		t := base
		for q := p; ; q = filepath.Dir(q) {
			if at, ok := s.Applied[q]; ok && at.After(t) {
				t = at
			}
			if q == filepath.Dir(q) {
				return t
			}
		}
	}
	var replaced []string
	for _, c := range cs {
		if c.Kind == review.Replaced {
			replaced = append(replaced, c.Path)
		}
	}
	var out []Conflict
	for _, c := range cs {
		if slices.ContainsFunc(replaced, func(r string) bool { return c.Path != r && within(c.Path, r) }) {
			continue // the check of the replaced directory covers what was in it
		}
		st, err := os.Lstat(c.Path)
		exists := err == nil
		switch c.Kind {
		case review.Added:
			switch {
			case exists && !(c.IsDir() && st.IsDir()):
				out = append(out, Conflict{c.Path, "created on the host during the session"})
			case !exists && slices.Contains(s.HostConfigs, c.Path):
				// An agent config the host removed: the branch copy
				// reads as new, but applying it would undo the removal.
				out = append(out, Conflict{c.Path, "deleted on the host during the session"})
			}
		default:
			if !exists {
				if c.Kind != review.Deleted {
					out = append(out, Conflict{c.Path, "deleted on the host during the session"})
				}
				continue
			}
			if st.IsDir() && (c.Kind == review.Deleted || c.Kind == review.Replaced) {
				if p := changedInside(c.Path, since); p != "" {
					out = append(out, Conflict{p, "changed on the host during the session, inside a directory the agent removed"})
				}
			} else if !st.IsDir() && changedAfter(c.Path, since(c.Path)) {
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
	return ctime(&st).After(t)
}

func changedInside(dir string, since func(string) time.Time) string {
	found := ""
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found != "" {
			return filepath.SkipAll
		}
		if !d.IsDir() && changedAfter(p, since(p)) {
			found = p
		}
		return nil
	})
	return found
}

func Apply(s *session.Session, cs []review.Change, box *outbox.Box, o Options) error {
	if o.Branch != "" {
		if err := ApplyBranch(s, cs, o.Branch, o); err != nil {
			return err
		}
		return runIntents(s, box, s.GitTouched, bufio.NewReader(o.In), o)
	}
	if g := interrupted(s); g != nil {
		return fmt.Errorf("an apply of session %s started %s did not finish; run `airbag rollback %s` to undo its part, then apply again",
			s.ID, g.Started.Format("15:04:05"), s.ID)
	}
	if s.Status == session.StatusApplied {
		return runIntents(s, box, s.GitTouched, bufio.NewReader(o.In), o)
	}
	if s.Status == session.StatusRunning {
		return fmt.Errorf("session %s is still running", s.ID)
	}
	in := bufio.NewReader(o.In)
	// What review folds in $HOME (caches, agent state) is left out: the
	// fold is why it needs no decision, and a download cache holds code
	// a host build runs as it is. --only naming it takes it anyway.
	// Agent state folded under a directory the agent replaced is kept
	// with it (~/.claude rebuilt): applying the replacement takes the
	// host's directory away. A cache there is left out all the same; the
	// host's copy goes to the undo journal with the rest.
	var replaced []string
	for _, c := range cs {
		if c.Kind == review.Replaced && c.IsDir() && !review.Dropped(c) {
			replaced = append(replaced, c.Path+string(filepath.Separator))
		}
	}
	var kept []review.Change
	dropped := 0
	for _, c := range cs {
		under := review.DroppedState(c) && slices.ContainsFunc(replaced, func(r string) bool { return strings.HasPrefix(c.Path, r) })
		if review.Dropped(c) && !under && !homeMatches(c, o.Only, s.Home) {
			dropped++
			continue
		}
		kept = append(kept, c)
	}
	cs = kept
	if dropped > 0 {
		fmt.Fprintf(o.Out, "Leaving out %d cache and agent state files in $HOME (name one with --only to take it)\n", dropped)
	}
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
			fmt.Fprintf(o.Out, "  %s: %s\n", review.OneLine(c.Path), c.Reason)
		}
		return fmt.Errorf("nothing applied; leave these out with apply -i or --only, rerun with --force to overwrite them, or discard the session")
	}
	// Before the undo journal moves anything: the journal would follow
	// such a link too. --force does not cover it, since the change would
	// land somewhere else, not overwrite a host edit.
	var replacing []string
	for _, c := range picked {
		if c.Kind == review.Replaced {
			replacing = append(replacing, c.Path)
		}
	}
	rs := rootsOf(s)
	for _, c := range picked {
		if err := rs.held(c.Path, c.Rel); err != nil {
			return fmt.Errorf("nothing applied: %w", err)
		}
		if err := parentsUnlinked(c, replacing); err != nil {
			return fmt.Errorf("nothing applied: %w", err)
		}
	}
	if len(picked) > 0 {
		gen, err := beginGeneration(s)
		if err != nil {
			return fmt.Errorf("start the undo journal: %w", err)
		}
		for _, c := range picked {
			if err := gen.apply(c); err != nil {
				left, rerr := gen.rollback(o.Out)
				return applyFailed(c.Path, s.ID, err, left, rerr)
			}
		}
		if err := gen.finish(); err != nil {
			return err
		}
		// What apply wrote matches the branch from now on: a later run's
		// change to it conflicts only with a host edit after this.
		// A file is recorded with its own change time, which a host edit
		// after it exceeds even on a coarse clock; the rest with now.
		now := time.Now()
		if s.Applied == nil {
			s.Applied = map[string]time.Time{}
		}
		for _, c := range picked {
			at := now
			var st unix.Stat_t
			if unix.Lstat(c.Path, &st) == nil && st.Mode&unix.S_IFMT != unix.S_IFDIR {
				at = ctime(&st)
			}
			s.Applied[c.Path] = at
		}
	}
	if !s.Clone {
		forget(picked) // a clone matches the real files once they are applied
	}
	if gitTouched(picked) {
		s.GitTouched = true
	}
	// A config this apply removed from the real $HOME, itself or with a
	// directory above it, is not one the host removed: a later run may
	// create it anew.
	s.HostConfigs = slices.DeleteFunc(s.HostConfigs, func(p string) bool {
		return slices.ContainsFunc(picked, func(c review.Change) bool {
			// A file or link in place of a directory removes it too,
			// though Scan calls that Modified.
			removed := c.Kind == review.Deleted || c.Kind == review.Replaced || c.Kind == review.Modified && !c.IsDir()
			return c.Kind == review.Deleted && c.Path == p || removed && strings.HasPrefix(p, c.Path+string(filepath.Separator))
		})
	})
	if len(picked) > 0 {
		fmt.Fprintf(o.Out, "Applied %d changes.\n", len(picked))
	}

	rest, err := review.Scan(s)
	if err != nil {
		return err
	}
	// What apply leaves out does not keep the session open.
	left := slices.DeleteFunc(slices.Clone(rest), review.Dropped)
	if len(left) == 0 {
		s.Status = session.StatusApplied
	} else {
		fmt.Fprintf(o.Out, "%d changes stay in session %s: airbag apply -i, or airbag discard.\n", len(left), s.ID)
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
// applyFailed says what a failed step left behind once the steps before
// it were rolled back: nothing, or paths the rollback could not undo.
func applyFailed(path, id string, err error, left int, rerr error) error {
	switch {
	case rerr != nil:
		return fmt.Errorf("%s: %w; rolling back what was applied also failed (%w), see `airbag rollback %s`", path, err, rerr, id)
	case left > 0:
		return fmt.Errorf("%s: %w; rolling back what was applied left %d paths as they are, see `airbag rollback %s`", path, err, left, id)
	}
	return fmt.Errorf("%s: %w; nothing applied, the changes are back in the session", path, err)
}

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
	lock, err := box.LockExecution()
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	intents, err := box.List()
	if err != nil {
		return err
	}
	if len(intents) > 0 {
		// Pushes and deferred commands run in the workspace.
		if err := rootsOf(s).check(s.Workspace); err != nil {
			return fmt.Errorf("the session's outbox waits: %w", err)
		}
	}
	// After a failure the rest wait (a PR without its push means
	// nothing), in this run; after an unknown outcome they wait until the
	// user records what happened with `airbag outbox resolve`. An intent
	// left pending (--yes, --branch, --trust-git) holds nothing back.
	failed, unknown := "", ""
	var links []string // the session's links out, looked for once
	looked := o.TrustLinks
	for _, it := range intents {
		if it.Status == outbox.Unknown {
			unknown = it.ID
			continue
		}
		if it.Status == outbox.Running {
			// A run was recorded but not its end: airbag stopped mid-push.
			it.Status = outbox.Unknown
			it.Output = "airbag stopped while this ran, so whether it took effect is not known; it is not run again"
			if it.Kind == outbox.KindPush {
				it.Output = "airbag stopped while this ran, so it may or may not have reached the remote " +
					"(check with git ls-remote); it is not run again"
			}
			if err := box.Update(it); err != nil {
				return fmt.Errorf("intent %s: %w", it.ID, err)
			}
			fmt.Fprintf(o.Out, "intent %s: %s\n", it.ID, it.Output)
			unknown = it.ID
			continue
		}
		if it.Status != outbox.Pending && !(it.Request != nil && it.Status == string(operation.Approved)) {
			continue
		}
		if unknown != "" {
			fmt.Fprintf(o.Out, "intent %s left pending: the outcome of %s is unknown; check what it did, then record it with "+
				"`airbag outbox resolve %s done|failed %s`, and `airbag apply %s` runs the rest\n",
				it.ID, unknown, unknown, s.ID, s.ID)
			continue
		}
		if failed != "" {
			fmt.Fprintf(o.Out, "intent %s left pending: %s failed before it; once that is sorted out, `airbag apply %s` runs the rest\n",
				it.ID, failed, s.ID)
			continue
		}
		var status string
		switch it.Kind {
		case outbox.KindPush:
			status, err = runPush(s, box, it, risky, in, o)
		case outbox.KindCmd:
			if !looked {
				links, looked = linksOut(s), true
			}
			status, err = runCmd(s, box, it, risky, links, in, o)
		case outbox.KindPullRequest:
			status, err = runPullRequest(s, box, it, in, o)
		default:
			status, err = reject(box, it, "unknown kind "+it.Kind, o)
		}
		if err != nil {
			return err
		}
		switch status {
		case outbox.Failed:
			failed = it.ID
		case outbox.Unknown:
			unknown = it.ID
		}
	}
	return nil
}

func reject(box *outbox.Box, it outbox.Intent, why string, o Options) (string, error) {
	it.Status, it.Output = outbox.Rejected, why
	fmt.Fprintf(o.Out, "intent %s rejected: %s\n", it.ID, why)
	if err := box.Update(it); err != nil {
		return "", fmt.Errorf("intent %s: %w", it.ID, err)
	}
	return outbox.Rejected, nil
}

// run records the start first: if airbag stops while the command runs,
// the next apply reports the outcome as unknown instead of running it
// again.
func run(box *outbox.Box, it outbox.Intent, cmd *exec.Cmd, o Options) (string, error) {
	it.Status = outbox.Running
	if err := box.Update(it); err != nil {
		return "", fmt.Errorf("intent %s not run: %w", it.ID, err)
	}
	outb, err := cmd.CombinedOutput()
	_, _ = o.Out.Write(outb)
	it.Output = clipOutput(string(outb))
	it.Status = outbox.Done
	if err != nil {
		it.Status = outbox.Failed
		fmt.Fprintf(o.Out, "intent %s failed: %v\n", it.ID, err)
	}
	if err := box.Update(it); err != nil {
		return "", fmt.Errorf("intent %s ran (%s), but its result was not recorded: %w", it.ID, it.Status, err)
	}
	return it.Status, nil
}

func clipOutput(s string) string {
	const max = 64 << 10
	if len(s) > max {
		return s[:max] + "\n[airbag: output clipped]"
	}
	return s
}

func runPush(s *session.Session, box *outbox.Box, it outbox.Intent, risky bool, in *bufio.Reader, o Options) (string, error) {
	if s.Branch != "" {
		// The push names the agent's branch, which is not the
		// user's: the work is on s.Branch now.
		fmt.Fprintf(o.Out, "intent %s (git %s) left pending: the session's work is on branch %s; "+
			"push that when ready (git push origin %s)\n", it.ID, strings.Join(it.Argv[1:], " "), s.Branch, s.Branch)
		return outbox.Pending, nil
	}
	cwd := hostDir(s, it.Cwd)
	args, err := outbox.GitPush(it.Argv)
	if err != nil || !within(cwd, s.Workspace) {
		return reject(box, it, fmt.Sprintf("invalid intent: %v (cwd %s)", err, it.Cwd), o)
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
			return outbox.Pending, nil
		}
		args = append([]string{"-c", "core.hooksPath=/dev/null"}, args...)
	}
	where := pushTarget(cwd, args)
	if !confirm(in, o, fmt.Sprintf("Run intent %s: `git %s` → %s?", it.ID, strings.Join(args, " "), where)) {
		it.Status = outbox.Rejected
		if err := box.Update(it); err != nil {
			return "", fmt.Errorf("intent %s: %w", it.ID, err)
		}
		return outbox.Rejected, nil
	}
	cmd := exec.CommandContext(context.Background(), "git", args...) //nolint:gosec // a push outbox.GitPush checked and the user confirmed
	cmd.Dir = cwd
	return run(box, it, cmd, o)
}

// runCmd runs a call a `defer:` entry held back. It runs on this
// machine with the user's credentials, so: the program comes from this
// machine's PATH and not from the workspace, the files it names must
// hold what they held when it was queued, and the user confirms each
// one; --yes does not.
func runCmd(s *session.Session, box *outbox.Box, it outbox.Intent, risky bool, links []string, in *bufio.Reader, o Options) (string, error) {
	line := outbox.Line(it.Argv)
	if s.Branch != "" {
		// The working tree is not the session's result, so there is
		// nothing for the command to act on; on the branch it may be.
		fmt.Fprintf(o.Out, "intent %s (`%s`) left pending: the session's work is on branch %s, not in the working tree; "+
			"run it yourself from that branch when it is ready\n", it.ID, line, s.Branch)
		return outbox.Pending, nil
	}
	cwd := hostDir(s, it.Cwd)
	if len(it.Argv) == 0 || strings.ContainsRune(it.Argv[0], '/') || !within(cwd, s.Workspace) {
		return reject(box, it, fmt.Sprintf("invalid intent (cwd %s)", it.Cwd), o)
	}
	prog, err := exec.LookPath(it.Argv[0])
	if err != nil {
		return reject(box, it, fmt.Sprintf("%s: not found on this machine", it.Argv[0]), o)
	}
	// The program's path has its links resolved, so the workspace's is
	// compared with its links resolved too (a workspace under ~/code ->
	// /mnt/data/code, or /tmp -> /private/tmp on macOS).
	ws := s.Workspace
	if r, err := filepath.EvalSymlinks(ws); err == nil {
		ws = r
	}
	if abs, err := filepath.EvalSymlinks(prog); err != nil || within(abs, ws) || within(abs, s.Workspace) {
		return reject(box, it, fmt.Sprintf("%s resolves to %s, inside the workspace; deferred commands run only programs from outside it", it.Argv[0], prog), o)
	}
	if a := namesSession(s, it.Argv[1:]); a != "" {
		return reject(box, it, fmt.Sprintf("%s names session %s's own storage, which holds what the agent wrote; "+
			"name the file in the workspace instead, or run it yourself", a, s.ID), o)
	}
	if len(links) > 0 {
		fmt.Fprintf(o.Out, "intent %s (`%s`) left pending: session %s put links in your files that lead out of the workspace "+
			"or to a secret file: %s. The command could read or write through them, which its arguments do not show. "+
			"Inspect them, then remove or replace them, or run `airbag apply --trust-links %s` if they are what you want\n",
			it.ID, line, s.ID, listLinks(links), s.ID)
		return outbox.Pending, nil
	}
	rels := make([]string, 0, len(it.Files))
	for rel := range it.Files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		p := filepath.Join(s.Workspace, filepath.FromSlash(rel))
		if !within(p, s.Workspace) {
			return reject(box, it, "invalid intent: file "+rel, o)
		}
		if got, err := hashFile(p); err != nil || got != it.Files[rel] {
			return reject(box, it, fmt.Sprintf("%s is not what it was when the command was queued; not run", rel), o)
		}
	}
	env := os.Environ()
	if risky {
		// The program may run git in the repository, and the agent's
		// git config can run code from there (hooks, fsmonitor).
		if !o.TrustGit {
			fmt.Fprintf(o.Out, "intent %s left pending: session %s changed .git/config or git hooks, which run on this "+
				"machine when a program uses git here. Inspect them (git config --local --list; ls .git/hooks), then run "+
				"`airbag apply --trust-git %s`\n", it.ID, s.ID, s.ID)
			return outbox.Pending, nil
		}
		env = append(env, "GIT_CONFIG_COUNT=2",
			"GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=/dev/null",
			"GIT_CONFIG_KEY_1=core.fsmonitor", "GIT_CONFIG_VALUE_1=false")
	}
	if o.Yes {
		fmt.Fprintf(o.Out, "intent %s (`%s`) left pending: commands other than git push are confirmed one by one; "+
			"run `airbag apply %s` without --yes\n", it.ID, line, s.ID)
		return outbox.Pending, nil
	}
	q := fmt.Sprintf("Run intent %s on this machine, with your credentials, in %s (it reads the workspace as applied):\n  %s\n",
		it.ID, cwd, line)
	q = strings.TrimSuffix(q, "\n")
	if !confirm(in, o, q) {
		it.Status = outbox.Rejected
		if err := box.Update(it); err != nil {
			return "", fmt.Errorf("intent %s: %w", it.ID, err)
		}
		return outbox.Rejected, nil
	}
	cmd := exec.CommandContext(context.Background(), prog, it.Argv[1:]...) //nolint:gosec // a deferred command: a program from this machine's PATH, its files checked, confirmed by the user
	cmd.Args[0] = it.Argv[0]
	cmd.Dir, cmd.Env = cwd, env
	return run(box, it, cmd, o)
}

// hostDir maps a directory the agent saw to the real workspace: on
// macOS the agent worked in the clone.
func hostDir(s *session.Session, dir string) string {
	if !s.Clone {
		return dir
	}
	clones := []string{s.CloneDir()}
	if r, err := filepath.EvalSymlinks(s.CloneDir()); err == nil {
		clones = append(clones, r)
	}
	for _, c := range clones {
		if within(dir, c) {
			rel, _ := filepath.Rel(c, dir)
			return filepath.Join(s.Workspace, rel)
		}
	}
	return dir
}

// linksOut lists the links this session put in the real files that a
// deferred command could read or write private data through: link and
// where it leads. A deferred command is confirmed by its arguments, and
// an argument that is, or runs through, such a link reaches its target
// without showing it (notes.md -> ~/.env, docs -> ~/.config). A link is
// harmless only when it stays in the workspace, or leads to an installed
// program (public); all else counts, any directory or configuration file
// outside, the user's home, other disks and the session's own storage
// included. Places are compared as files, not
// as names, so case and firmlinks on macOS do not matter. Each link is
// checked as it is now: one the user removed or replaced no longer counts.
func linksOut(s *session.Session) []string {
	ws, err := os.Stat(s.Workspace)
	if err != nil {
		return []string{"the workspace " + s.Workspace + " itself, which cannot be read"}
	}
	paths := make([]string, 0, len(s.Applied))
	for p := range s.Applied {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var out []string
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
			continue
		}
		t, ok := linkTarget(p)
		switch {
		case !ok:
			out = append(out, p+" -> (nowhere)")
		case secretfs.IsSecret(strings.ToLower(filepath.Base(t))):
			out = append(out, p+" -> "+t)
		case inside(t, ws):
		case !public(t):
			out = append(out, p+" -> "+t)
		}
	}
	return out
}

// linkTarget is where link p leads, the part that does not exist yet
// joined on as written; ok is false for a loop or a link on the way
// that leads nowhere.
func linkTarget(p string) (string, bool) {
	if t, err := filepath.EvalSymlinks(p); err == nil {
		return t, true
	}
	text, err := os.Readlink(p)
	if err != nil {
		return "", false
	}
	dir := "/"
	if !filepath.IsAbs(text) {
		if dir, err = filepath.EvalSymlinks(filepath.Dir(p)); err != nil {
			return "", false
		}
	}
	return follow(dir, text)
}

// inside reports whether p, or the nearest part of it that exists, is
// below the directory root, comparing files rather than names.
func inside(p string, root os.FileInfo) bool {
	for d := p; ; d = filepath.Dir(d) {
		if fi, err := os.Stat(d); err == nil && os.SameFile(fi, root) {
			return true
		}
		if filepath.Dir(d) == d {
			return false
		}
	}
}

// public reports whether p is an installed program, which is what a
// venv's interpreter links to: a regular file with an execute bit, owned
// by root, in directories owned by root that anyone may search, none of
// them writable by the user. Other files anyone may read are not public:
// a machine's configuration can carry credentials, and a file root wrote
// into a user's folder can be the user's data. A directory never is: what
// lies below it is not known, and on macOS firmlinks join user data into
// /usr and /System. Something that does not exist is not public either:
// what appears there later, a process's files under /proc among them, is
// not known now.
func public(p string) bool {
	file, ok := placeOf(p)
	if !ok {
		return false
	}
	var dirs []place
	for d := filepath.Dir(p); ; d = filepath.Dir(d) {
		dir, ok := placeOf(d)
		if !ok {
			return false
		}
		dirs = append(dirs, dir)
		if filepath.Dir(d) == d {
			break
		}
	}
	return program(file, dirs)
}

// place is what public looks at in a file or directory: its mode, owner,
// and whether the user may write it.
type place struct {
	mode     fs.FileMode
	uid      int64
	writable bool
}

func placeOf(p string) (place, bool) {
	fi, err := os.Stat(p)
	if err != nil {
		return place{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return place{}, false
	}
	return place{mode: fi.Mode(), uid: int64(st.Uid), writable: unix.Access(p, unix.W_OK) == nil}, true
}

// program reports whether file, below dirs, is an installed program: see
// public.
func program(file place, dirs []place) bool {
	if !file.mode.IsRegular() || file.mode&0o111 == 0 || file.uid != 0 || file.writable {
		return false
	}
	for _, d := range dirs {
		if !d.mode.IsDir() || d.mode&0o001 == 0 || d.uid != 0 || d.writable {
			return false
		}
	}
	return true
}

// listLinks names up to three links, and how many more.
func listLinks(links []string) string {
	shown := links[:min(3, len(links))]
	out := strings.Join(shown, ", ")
	if n := len(links) - len(shown); n > 0 {
		out += fmt.Sprintf(" and %d more", n)
	}
	return out
}

// namesSession returns the first argument that names this session's own
// storage (the clone or upper layer, which hold what the agent wrote and,
// on macOS, copies of your files, links included), in any spelling that
// carries the session's ID.
func namesSession(s *session.Session, args []string) string {
	id := strings.ToLower(s.ID)
	for _, a := range args {
		if id != "" && strings.Contains(strings.ToLower(a), id) {
			return a
		}
	}
	return ""
}

// follow resolves name from the real directory dir one component at a
// time, as the kernel does: a link is replaced by where it leads before
// a later ".." applies. The part that does not exist yet is joined on as
// written. ok is false for a link on the way that leads nowhere or a
// loop of links.
func follow(dir, name string) (string, bool) {
	cur := dir
	parts := strings.Split(name, "/")
	for i, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, part)
		fi, err := os.Lstat(next)
		if err != nil {
			return filepath.Join(append([]string{next}, parts[i+1:]...)...), true
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			if next, err = filepath.EvalSymlinks(next); err != nil {
				return "", false
			}
		}
		cur = next
	}
	return cur, true
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // read only
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
	out, err := exec.CommandContext(context.Background(), "git", "-C", cwd, "remote", "get-url", "--push", remote).Output() //nolint:gosec // remote is an argument that does not start with "-"
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
	if err := parentsUnlinked(c, nil); err != nil {
		return err
	}
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
		// Its directory, when new, is not applied on its own (Units: it
		// is made along with what is in it), as copyFile does for files.
		if err := os.MkdirAll(filepath.Dir(c.Path), 0o755); err != nil { //nolint:gosec // a directory in the user's workspace, with the usual mode less the umask
			return err
		}
		_ = os.Remove(c.Path)
		return os.Symlink(target, c.Path)
	default:
		return copyFile(c.Upper, c.Path, c.Mode)
	}
}

// parentsUnlinked refuses a change when a directory on its way down from
// its layer's root is a link on the host now. In the session that place
// was a directory (the branch holds an entry below it), so the link is
// the host's, made while the session ran, and only the entry itself was
// checked for a conflict: writing or removing through it would land
// outside the workspace or $HOME. A directory in replacing is not looked
// below: its own change, applied first, makes it a real directory.
func parentsUnlinked(c review.Change, replacing []string) error {
	rel := filepath.FromSlash(c.Rel)
	root, ok := strings.CutSuffix(c.Path, string(filepath.Separator)+rel)
	if !ok {
		return fmt.Errorf("%s is not %s in its layer", c.Path, c.Rel)
	}
	d := root
	for _, part := range strings.Split(filepath.Dir(rel), string(filepath.Separator)) {
		if part == "." {
			break
		}
		d = filepath.Join(d, part)
		if slices.Contains(replacing, d) {
			return nil
		}
		fi, err := os.Lstat(d)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return nil // made below as a directory, or a file in the way that the apply stops at
		}
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s became a link on the host, so %s would land where it leads; remove the link or leave the change out", d, c.Rel)
		}
	}
	return nil
}

// roots maps the workspace and $HOME, as the session names them, to the
// directories they were when it began.
type roots map[string]session.DirID

func rootsOf(s *session.Session) roots {
	r := roots{}
	if s.WorkspaceID.Real != "" {
		r[s.Workspace] = s.WorkspaceID
	}
	if s.HomeID.Real != "" {
		r[s.Home] = s.HomeID
	}
	return r
}

// check refuses a root that is another directory than when the session
// began: the host renamed the workspace and put a link or a new
// directory in its place, say. Every change below it, a new top-level
// file included, would land there. A path the session did not record
// (a session from before roots were recorded) is not checked.
func (r roots) check(root string) error {
	want, ok := r[root]
	if !ok {
		return nil
	}
	got, err := session.DirIDOf(root)
	switch {
	case err != nil:
		return fmt.Errorf("%s, the session's root: %w", root, err)
	case got.Real != want.Real:
		return fmt.Errorf("%s leads to %s now, not to %s as when the session began, so the changes would land there; put the directory back or discard the session", root, got.Real, want.Real)
	case got.Dev != want.Dev || got.Ino != want.Ino:
		return fmt.Errorf("%s is another directory than when the session began (that one was moved or removed), so the changes would land in this one; put the directory back or discard the session", root)
	}
	return nil
}

// held checks the root of the layer a path at rel belongs to.
func (r roots) held(path, rel string) error {
	root, ok := strings.CutSuffix(path, string(filepath.Separator)+filepath.FromSlash(rel))
	if !ok {
		return fmt.Errorf("%s is not %s in its layer", path, rel)
	}
	return r.check(root)
}

// copyFile replaces dst atomically: write a temp file next to it, then
// rename over the old one.
func copyFile(src, dst string, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // a directory in the user's workspace, with the usual mode less the umask
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }() // read only
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".airbag-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // gone after the rename
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
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
