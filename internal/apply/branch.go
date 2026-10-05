package apply

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/getjump/airbag/internal/review"
	"github.com/getjump/airbag/internal/session"
)

// ApplyBranch puts the session's workspace result on a new branch of the
// real repository and leaves everything else alone: the working tree,
// the index, .git/config and hooks are not touched, so the user goes on
// working and merges the branch when ready, with git.
//
// The branch is the agent's last commit, fetched from the session (its
// history comes along), plus one commit with whatever the agent left
// uncommitted, if anything. Git config and hooks the agent changed are
// not carried over: only objects and the commit graph are.
//
// Ignored files are left out by the real repository's ignore rules; a
// .gitignore the agent changed is not consulted.
func ApplyBranch(s *session.Session, cs []review.Change, name string, o Options) error {
	ws := s.Workspace
	if s.Status == session.StatusRunning {
		return fmt.Errorf("session %s is still running", s.ID)
	}
	if err := rootsOf(s).check("ws"); err != nil {
		return fmt.Errorf("nothing applied: %w; put the directory back or discard the session", err) // the branch would go to that repository
	}
	if out, err := git(ws, nil, "rev-parse", "--git-dir"); err != nil || strings.TrimSpace(out) != ".git" {
		return fmt.Errorf("--branch needs the workspace to be the top of a git repository")
	}
	if _, err := git(ws, nil, "check-ref-format", "--branch", name); err != nil {
		return fmt.Errorf("%q is not a valid branch name", name)
	}
	if _, err := git(ws, nil, "rev-parse", "--verify", "--quiet", "refs/heads/"+name); err == nil {
		return fmt.Errorf("branch %s already exists", name)
	}

	head, err := agentHead(s)
	if err != nil {
		return fmt.Errorf("the agent's HEAD: %w", err)
	}
	commits := 0
	if head != "" {
		if err := fetchAgent(s, head); err != nil {
			return err
		}
		if out, err := git(ws, nil, "rev-list", "--count", head, "--not", "--exclude=refs/airbag/*", "--all"); err == nil {
			_, _ = fmt.Sscan(strings.TrimSpace(out), &commits) // only counted for the message
		}
	} else if out, err := git(ws, nil, "rev-parse", "HEAD"); err == nil {
		head = strings.TrimSpace(out)
	} else {
		return fmt.Errorf("the repository has no commit to branch from")
	}

	tip, files, err := commitLeftovers(s, cs, head)
	if err != nil {
		return err
	}
	if _, err := git(ws, nil, "update-ref", "-m", "airbag: session "+s.ID, "refs/heads/"+name, tip, strings.Repeat("0", len(tip))); err != nil {
		return fmt.Errorf("create branch %s: %w", name, err)
	}

	s.Branch = name
	var wsChanges, home []review.Change
	for _, c := range cs {
		if c.Layer == "ws" {
			wsChanges = append(wsChanges, c)
		} else if !review.Dropped(c) {
			home = append(home, c) // what apply leaves out does not keep the session open
		}
	}
	if !s.Clone {
		forget(wsChanges)
	}
	if len(home) == 0 {
		s.Status = session.StatusApplied
	}
	if err := s.Save(); err != nil {
		return err
	}
	fmt.Fprintf(o.Out, "Branch %s at %s: %d commits by the agent", name, short(tip), commits)
	if files > 0 {
		fmt.Fprintf(o.Out, ", then %d files it left uncommitted", files)
	}
	fmt.Fprintln(o.Out, ". Your working tree is untouched; merge when ready:")
	fmt.Fprintf(o.Out, "  git log --stat HEAD..%s\n  git merge %s\n", name, name)
	if len(home) > 0 {
		fmt.Fprintf(o.Out, "%d changes in ~ stay in session %s: airbag apply -i, or airbag discard.\n", len(home), s.ID)
	}
	return nil
}

// agentHead returns the commit the agent's HEAD points to in the
// branch, or "" when the session did not move HEAD (no commits).
func agentHead(s *session.Session) (string, error) {
	upper, lower := filepath.Join(s.WSBranch(), ".git"), filepath.Join(s.Workspace, ".git")
	read := func(rel string) ([]byte, bool) {
		for _, dir := range []string{upper, lower} {
			p := filepath.Join(dir, rel)
			st, err := os.Lstat(p)
			if err != nil {
				continue
			}
			if !st.Mode().IsRegular() {
				return nil, false // a whiteout: deleted in the branch
			}
			b, err := os.ReadFile(p)
			return b, err == nil
		}
		return nil, false
	}
	resolve := func() (string, error) {
		ref := "HEAD"
		for i := 0; i < 5; i++ {
			b, ok := read(ref)
			if !ok {
				// Packed refs: the branch's copy shadows the real one.
				if pr, ok := read("packed-refs"); ok {
					for _, l := range strings.Split(string(pr), "\n") {
						if f := strings.Fields(l); len(f) == 2 && f[1] == ref {
							return f[0], nil
						}
					}
				}
				return "", fmt.Errorf("cannot resolve %s", ref)
			}
			v := strings.TrimSpace(string(b))
			if r, ok := strings.CutPrefix(v, "ref: "); ok {
				ref = r
				continue
			}
			return v, nil
		}
		return "", errors.New("symbolic refs nest too deep")
	}
	sha, err := resolve()
	if err != nil {
		return "", err
	}
	// The agent wrote what HEAD holds, and it goes to git on this
	// machine as an argument: "--output=..." would be an option there.
	if !isObjectID(sha) {
		return "", errors.New("HEAD does not name a commit")
	}
	real, err := git(s.Workspace, nil, "rev-parse", "HEAD")
	if err == nil && strings.TrimSpace(real) == sha {
		return "", nil
	}
	return sha, nil
}

// fetchAgent copies the agent's commits into the real repository as
// refs/airbag/<session>/head. The branch's object store is the real one
// plus the new objects in the upper layer; a throwaway bare repository
// sees both through alternates, and the real repository fetches from
// it. The fetch runs with hooks off and does not read the agent's
// config.
func fetchAgent(s *session.Session, head string) error {
	tmp, err := os.MkdirTemp(s.Dir, "fetch-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }() // a scratch repository in the session dir
	if _, err := git("", nil, "init", "-q", "--bare", tmp); err != nil {
		return err
	}
	realObjects, err := git(s.Workspace, nil, "rev-parse", "--path-format=absolute", "--git-path", "objects")
	if err != nil {
		return err
	}
	alt := strings.TrimSpace(realObjects) + "\n" + filepath.Join(s.WSBranch(), ".git", "objects") + "\n"
	if err := os.WriteFile(filepath.Join(tmp, "objects", "info", "alternates"), []byte(alt), 0o600); err != nil {
		return err
	}
	if _, err := git("", nil, "--git-dir", tmp, "update-ref", "refs/heads/agent", head); err != nil {
		return fmt.Errorf("the agent's commit %s is not readable: %w", short(head), err)
	}
	ref := "refs/airbag/" + s.ID + "/head"
	if _, err := git(s.Workspace, nil, "-c", "core.hooksPath=/dev/null", "fetch", "-q", "--no-tags",
		"--no-write-fetch-head", tmp, "+refs/heads/agent:"+ref); err != nil {
		return fmt.Errorf("fetch the agent's commits: %w", err)
	}
	return nil
}

// commitLeftovers commits what the agent left uncommitted on top of
// base, through a temporary index. It returns the new tip (base when
// nothing was left) and the number of files in that commit.
func commitLeftovers(s *session.Session, cs []review.Change, base string) (string, int, error) {
	ws := s.Workspace
	idx := filepath.Join(s.Dir, "branch.index")
	defer func() { _ = os.Remove(idx) }() // a scratch index in the session dir
	env := []string{"GIT_INDEX_FILE=" + idx}
	if _, err := git(ws, env, "read-tree", base); err != nil {
		return "", 0, err
	}

	var drop []string
	var keep []review.Change
	for _, c := range cs {
		if c.Layer != "ws" || isGitPath(c.Rel) {
			continue
		}
		switch {
		case c.Kind == review.Deleted || c.Kind == review.Replaced:
			drop = append(drop, filepath.ToSlash(c.Rel))
		}
		if c.Kind != review.Deleted && !c.IsDir() {
			keep = append(keep, c)
		}
	}
	keep, err := notIgnored(ws, keep)
	if err != nil {
		return "", 0, err
	}
	if len(drop) > 0 {
		args := append([]string{"rm", "-r", "-q", "--cached", "--ignore-unmatch", "--"}, drop...)
		if _, err := git(ws, env, args...); err != nil {
			return "", 0, err
		}
	}
	var info bytes.Buffer
	for _, c := range keep {
		mode := "100644"
		var sha string
		var err error
		switch {
		case c.Type == fs.ModeSymlink:
			target, rerr := os.Readlink(c.Upper)
			if rerr != nil {
				return "", 0, rerr
			}
			mode = "120000"
			sha, err = gitIn(ws, nil, strings.NewReader(target), "hash-object", "-w", "--stdin")
		default:
			if c.Mode&0o111 != 0 {
				mode = "100755"
			}
			sha, err = git(ws, nil, "hash-object", "-w", "--path", filepath.ToSlash(c.Rel), c.Upper)
		}
		if err != nil {
			return "", 0, fmt.Errorf("%s: %w", c.Rel, err)
		}
		fmt.Fprintf(&info, "%s %s\t%s\n", mode, strings.TrimSpace(sha), filepath.ToSlash(c.Rel))
	}
	if info.Len() > 0 {
		if _, err := gitIn(ws, env, &info, "update-index", "--index-info"); err != nil {
			return "", 0, err
		}
	}
	tree, err := git(ws, env, "write-tree")
	if err != nil {
		return "", 0, err
	}
	baseTree, err := git(ws, nil, "rev-parse", base+"^{tree}")
	if err != nil {
		return "", 0, err
	}
	if strings.TrimSpace(tree) == strings.TrimSpace(baseTree) {
		return base, 0, nil
	}
	n := 0
	if out, err := git(ws, nil, "diff-tree", "-r", "--name-only", "--no-commit-id", base, strings.TrimSpace(tree)); err == nil {
		n = len(strings.Fields(out))
	}
	msg := "airbag: files the agent left uncommitted in session " + s.ID
	tip, err := git(ws, nil, "commit-tree", strings.TrimSpace(tree), "-p", base, "-m", msg)
	if err != nil {
		return "", 0, fmt.Errorf("commit: %w", err)
	}
	return strings.TrimSpace(tip), n, nil
}

// notIgnored drops changes the real repository's ignore rules exclude:
// build output and dependencies stay out of the branch.
func notIgnored(ws string, cs []review.Change) ([]review.Change, error) {
	if len(cs) == 0 {
		return cs, nil
	}
	var in bytes.Buffer
	for _, c := range cs {
		in.WriteString(filepath.ToSlash(c.Rel) + "\x00")
	}
	out, err := gitIn(ws, nil, &in, "check-ignore", "--no-index", "-z", "--stdin")
	if err != nil && out == "" {
		return cs, nil // exit 1: nothing is ignored
	}
	ignored := map[string]bool{}
	for _, p := range strings.Split(out, "\x00") {
		if p != "" {
			ignored[p] = true
		}
	}
	var keep []review.Change
	for _, c := range cs {
		if !ignored[filepath.ToSlash(c.Rel)] {
			keep = append(keep, c)
		}
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].Rel < keep[j].Rel })
	return keep, nil
}

// isObjectID reports whether s is a SHA-1 or SHA-256 object name.
func isObjectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isGitPath(rel string) bool {
	for _, p := range strings.Split(filepath.ToSlash(rel), "/") {
		if p == ".git" {
			return true
		}
	}
	return false
}

func git(dir string, env []string, args ...string) (string, error) {
	return gitIn(dir, env, nil, args...)
}

func gitIn(dir string, env []string, stdin io.Reader, args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), "git", args...) //nolint:gosec // callers pass their own subcommands; paths from the sandbox follow "--" or an option that takes them
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return string(out), fmt.Errorf("git %s: %s", args[0], firstLine(msg))
		}
		return string(out), err
	}
	return string(out), nil
}

func firstLine(s string) string {
	sc := bufio.NewScanner(strings.NewReader(s))
	if sc.Scan() {
		return sc.Text()
	}
	return s
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
