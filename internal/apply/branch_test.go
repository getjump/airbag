package apply

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/review"
)

// The branch's HEAD is the agent's to write; only an object name gets
// through to git on the host, where anything else could be an option.
func TestAgentHeadIsAnObjectID(t *testing.T) {
	s, _ := undoSession(t)
	git := filepath.Join(s.WSBranch(), ".git")
	if err := os.MkdirAll(filepath.Join(git, "refs", "heads"), 0o755); err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("ab", 20)
	for _, c := range []struct {
		head, ref string
		ok        bool
	}{
		{sha + "\n", "", true},
		{"ref: refs/heads/main\n", sha + "\n", true},
		{"--output=/tmp/x\n", "", false},
		{"ref: refs/heads/main\n", "--output=/tmp/x\n", false},
		{strings.ToUpper(sha) + "\n", "", false},
		{sha[:39] + "\n", "", false},
	} {
		if err := os.WriteFile(filepath.Join(git, "HEAD"), []byte(c.head), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(git, "refs", "heads", "main"), []byte(c.ref), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := agentHead(s)
		if c.ok && (err != nil || got != sha) {
			t.Errorf("HEAD %q ref %q: %q, %v", c.head, c.ref, got, err)
		}
		if !c.ok && err == nil {
			t.Errorf("HEAD %q ref %q: accepted as %q", c.head, c.ref, got)
		}
	}
}

// The workspace is checked again before each step that writes to the
// repository: one replaced while the branch is being made gets no
// branch, and neither does the one moved away.
func TestBranchRechecksRoot(t *testing.T) {
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	ws := filepath.Join(t.TempDir(), "ws")
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), real, append([]string{"-C", dir}, args...)...) //nolint:gosec // test-owned repository
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %q: %s %v", args, out, err)
		}
	}
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	run(ws, "init", "-q")
	run(ws, "commit", "-q", "--allow-empty", "-m", "base")
	s := rootSession(t, ws)
	// Right after the last read before the branch is written, git moves
	// the workspace away and makes another repository at its path.
	bin, mark := t.TempDir(), filepath.Join(t.TempDir(), "moved")
	script := "#!/bin/sh\ncase \"$*\" in *\"^{tree}\"*)\n" +
		"  out=$(" + real + " \"$@\"); rc=$?\n" +
		"  if [ ! -e " + mark + " ]; then : > " + mark + "; mv " + ws + " " + ws + ".old && mkdir " + ws + " && " + real + " -C " + ws + " init -q; fi\n" +
		"  printf '%s\\n' \"$out\"; exit $rc ;;\nesac\n" +
		"exec " + real + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var out strings.Builder
	err = ApplyBranch(s, nil, "agent-work", Options{Out: &out})
	if _, statErr := os.Stat(mark); statErr != nil {
		t.Fatalf("the workspace was not moved: %v %v", err, statErr)
	}
	if err == nil || !strings.Contains(err.Error(), "no branch made") {
		t.Fatalf("made a branch in a replaced workspace: %v %q", err, out.String())
	}
	for _, dir := range []string{ws, ws + ".old"} {
		if _, err := os.Stat(filepath.Join(dir, ".git", "refs", "heads", "agent-work")); !os.IsNotExist(err) {
			t.Fatalf("%s got the branch: %v", dir, err)
		}
	}
}

// Between the writes of the agent's uncommitted files too: a workspace
// replaced after the first object is written takes no further git call.
func TestBranchRechecksRootBetweenWrites(t *testing.T) {
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	ws := filepath.Join(t.TempDir(), "ws")
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), real, append([]string{"-C", dir}, args...)...) //nolint:gosec // test-owned repository
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %q: %s %v", args, out, err)
		}
	}
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	run(ws, "init", "-q")
	run(ws, "commit", "-q", "--allow-empty", "-m", "base")
	s := rootSession(t, ws)
	if err := os.MkdirAll(s.WSBranch(), 0o755); err != nil {
		t.Fatal(err)
	}
	upper := filepath.Join(s.WSBranch(), "new.txt")
	if err := os.WriteFile(upper, []byte("agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cs := []review.Change{{Layer: "ws", Rel: "new.txt", Path: filepath.Join(ws, "new.txt"), Upper: upper, Kind: review.Added, Mode: 0o644}}
	// After the first object is written, git moves the workspace away,
	// puts another repository at its path, and logs every later call.
	bin, mark, log := t.TempDir(), filepath.Join(t.TempDir(), "moved"), filepath.Join(t.TempDir(), "after")
	script := "#!/bin/sh\nif [ -e " + mark + " ]; then echo \"$*\" >> " + log + "; fi\n" +
		"case \" $* \" in *\" hash-object \"*)\n" +
		"  out=$(" + real + " \"$@\"); rc=$?\n" +
		"  if [ ! -e " + mark + " ]; then : > " + mark + "; mv " + ws + " " + ws + ".old && mkdir " + ws + " && " + real + " -C " + ws + " init -q; fi\n" +
		"  printf '%s\\n' \"$out\"; exit $rc ;;\nesac\n" +
		"exec " + real + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var out strings.Builder
	err = ApplyBranch(s, cs, "agent-work", Options{Out: &out})
	if _, statErr := os.Stat(mark); statErr != nil {
		t.Fatalf("no object was written: %v %v", err, statErr)
	}
	if err == nil || !strings.Contains(err.Error(), "no branch made") {
		t.Fatalf("went on in a replaced workspace: %v %q", err, out.String())
	}
	if b, _ := os.ReadFile(log); len(b) != 0 {
		t.Fatalf("git ran in the replaced workspace: %s", b)
	}
}
