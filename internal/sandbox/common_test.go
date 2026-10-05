package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

func TestClaudeProjectSlug(t *testing.T) {
	for in, want := range map[string]string{
		"/home/me/src/api":     "-home-me-src-api",
		"/home/me/my_proj":     "-home-me-my-proj",
		"/home/me/a.b c/d":     "-home-me-a-b-c-d",
		"/home/me/caf\u00e9/x": "-home-me-caf--x",
		// Outside the BMP: two UTF-16 code units, two dashes.
		"/work/\U0001F600": "-work---",
	} {
		if got := ClaudeProjectSlug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
	if pass, holes := ClaudeProjectState("/"+strings.Repeat("a", 250), ""); len(pass)+len(holes) != 0 {
		t.Errorf("a slug Claude Code hashes passes through: %v %v", pass, holes)
	}
}

// Claude Code names a project by the physical path; started from a path
// through a symlink, airbag covers that spelling too.
func TestClaudeProjectStateResolvesSymlinks(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	physical, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	pass, _ := ClaudeProjectState(link, "")
	if !slices.Contains(pass, ".claude/projects/"+ClaudeProjectSlug(physical)+"/") ||
		!slices.Contains(pass, ".claude/projects/"+ClaudeProjectSlug(link)+"/") {
		t.Fatalf("pass = %v, want both spellings", pass)
	}
}

// A session an older airbag created stored the old, wide passthrough;
// resuming it keeps only today's list and the project directories.
func TestNarrowPassthrough(t *testing.T) {
	s := &session.Session{Meta: session.Meta{
		Passthrough: []string{".claude/projects/", ".claude/sessions/", ".claude.json", ".claude/.credentials.json",
			".claude/projects/-w/", ".claude/projects/../", ".claude/projects/a/b/", ".codex/sessions/"},
		BranchHoles: []string{".claude/projects/x/memory"},
	}}
	NarrowPassthrough(s)
	want := append(append([]string{}, DefaultPassthrough...), ".claude/projects/-w/")
	if !slices.Equal(s.Passthrough, want) || !slices.Equal(s.BranchHoles, []string{".claude/projects/-w/memory"}) {
		t.Fatalf("passthrough %v holes %v, want %v and the one hole", s.Passthrough, s.BranchHoles, want)
	}
}

func TestClaudeProjectState(t *testing.T) {
	// cwd inside the repo: transcripts under the cwd slug, memory under
	// both the cwd and the git-root slug, each held in the branch.
	pass, holes := ClaudeProjectState("/home/me/api/sub", "/home/me/api")
	wantPass := []string{".claude/projects/-home-me-api-sub/", ".claude/projects/-home-me-api/"}
	wantHoles := []string{".claude/projects/-home-me-api-sub/memory", ".claude/projects/-home-me-api/memory"}
	if !slices.Equal(pass, wantPass) {
		t.Errorf("pass = %v, want %v", pass, wantPass)
	}
	if !slices.Equal(holes, wantHoles) {
		t.Errorf("holes = %v, want %v", holes, wantHoles)
	}

	// cwd at the repo root: a single directory, no duplicate.
	pass, holes = ClaudeProjectState("/home/me/api", "/home/me/api")
	if !slices.Equal(pass, []string{".claude/projects/-home-me-api/"}) {
		t.Errorf("pass at root = %v", pass)
	}
	if !slices.Equal(holes, []string{".claude/projects/-home-me-api/memory"}) {
		t.Errorf("holes at root = %v", holes)
	}

	// No git root.
	pass, _ = ClaudeProjectState("/home/me/loose", "")
	if !slices.Equal(pass, []string{".claude/projects/-home-me-loose/"}) {
		t.Errorf("pass without root = %v", pass)
	}
}

func TestAddClaudeProjectStateOnResume(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	pass, holes := ClaudeProjectState("/home/me/api", "/home/me/api")
	s, err := session.Create(session.Meta{Workspace: "/home/me/api", Home: t.TempDir(),
		Passthrough: append(append([]string{}, DefaultPassthrough...), pass...), BranchHoles: holes})
	if err != nil {
		t.Fatal(err)
	}
	// Resumed from a subdirectory: its transcript directory joins, the
	// stored ones stay, nothing is listed twice, and doing it again
	// changes nothing.
	AddClaudeProjectState(s, "/home/me/api/sub")
	AddClaudeProjectState(s, "/home/me/api/sub")
	for _, want := range append([]string{".claude/projects/-home-me-api-sub/", ".claude/projects/-home-me-api/"}, DefaultPassthrough...) {
		if n := countOf(s.Passthrough, want); n != 1 {
			t.Errorf("passthrough has %q %d times: %v", want, n, s.Passthrough)
		}
	}
	for _, want := range []string{".claude/projects/-home-me-api-sub/memory", ".claude/projects/-home-me-api/memory"} {
		if n := countOf(s.BranchHoles, want); n != 1 {
			t.Errorf("holes have %q %d times: %v", want, n, s.BranchHoles)
		}
	}
}

func countOf(list []string, s string) int {
	n := 0
	for _, x := range list {
		if x == s {
			n++
		}
	}
	return n
}

// Resumed from a subdirectory whose project directory an earlier run
// already changed in the branch: it stays in the branch (no passthrough,
// no hole), so review and apply see one consistent tree.
func TestAddClaudeProjectStateKeepsBranchedDir(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	pass, holes := ClaudeProjectState("/home/me/api", "/home/me/api")
	s, err := session.Create(session.Meta{Workspace: "/home/me/api", Home: t.TempDir(),
		Passthrough: append(append([]string{}, DefaultPassthrough...), pass...), BranchHoles: holes})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.HomeUpper(), ".claude/projects/-home-me-api-sub")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "old.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	AddClaudeProjectState(s, "/home/me/api/sub")
	if slices.Contains(s.Passthrough, ".claude/projects/-home-me-api-sub/") {
		t.Errorf("a project dir the branch holds passes through: %v", s.Passthrough)
	}
	if slices.Contains(s.BranchHoles, ".claude/projects/-home-me-api-sub/memory") {
		t.Errorf("a hole under a branched project dir: %v", s.BranchHoles)
	}
}

// Plain directories alone in the branch, as apply leaves the copied-up
// ancestors of what it took, are not a change: the directory passes
// through.
func TestAddClaudeProjectStateIgnoresEmptyScaffolding(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	pass, holes := ClaudeProjectState("/home/me/api", "/home/me/api")
	s, err := session.Create(session.Meta{Workspace: "/home/me/api", Home: t.TempDir(),
		Passthrough: append(append([]string{}, DefaultPassthrough...), pass...), BranchHoles: holes})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.HomeUpper(), ".claude/projects/-home-me-api-sub/memory"), 0o700); err != nil {
		t.Fatal(err)
	}
	AddClaudeProjectState(s, "/home/me/api/sub")
	if !slices.Contains(s.Passthrough, ".claude/projects/-home-me-api-sub/") {
		t.Errorf("empty copied-up directories kept the project dir in the branch: %v", s.Passthrough)
	}
}

// A file with another name keeps the passed-through path it is in out
// of the passthrough: written through its name there, it would change
// for real. A memory file in a hole of the path counts too.
func TestHardLinks(t *testing.T) {
	home := t.TempDir()
	proj, hole := ".claude/projects/x", ".claude/projects/x/memory"
	if err := os.MkdirAll(filepath.Join(home, hole), 0o700); err != nil {
		t.Fatal(err)
	}
	mem := filepath.Join(home, hole, "MEMORY.md")
	for _, f := range []string{mem, filepath.Join(home, proj, "s.jsonl"), filepath.Join(home, ".bashrc"), filepath.Join(home, ".claude/.credentials.json")} {
		if err := os.WriteFile(f, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(p string, want []string) {
		t.Helper()
		got, full := hardLinks(home, p)
		if !full || strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: %v (full %v), want %v", p, got, full, want)
		}
	}
	check(proj, nil)
	check(".claude/.credentials.json", nil)
	check(".claude/projects/y", nil) // not there
	if err := os.Link(mem, filepath.Join(home, proj, "t.jsonl")); err != nil {
		t.Fatal(err)
	}
	check(proj, []string{hole + "/MEMORY.md", proj + "/t.jsonl"})
	if err := os.Remove(filepath.Join(home, proj, "t.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(home, ".bashrc"), filepath.Join(home, proj, "b.jsonl")); err != nil {
		t.Fatal(err)
	}
	check(proj, []string{proj + "/b.jsonl"})
	if err := os.Link(filepath.Join(home, ".claude/.credentials.json"), filepath.Join(home, ".claude.json")); err != nil {
		t.Fatal(err)
	}
	check(".claude/.credentials.json", []string{".claude/.credentials.json"})
}

// Past maxPassFiles regular files a path is not known to be free of
// hard links; directories do not count toward it.
func TestHardLinksCapped(t *testing.T) {
	home := t.TempDir()
	for _, f := range []string{"a/1", "a/2", "a/b/c/3"} {
		if err := os.MkdirAll(filepath.Join(home, filepath.Dir(f)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	defer func(n int) { maxPassFiles = n }(maxPassFiles)
	maxPassFiles = 3
	if _, full := hardLinks(home, "a"); !full {
		t.Error("three files and three directories counted past a cap of 3")
	}
	maxPassFiles = 2
	if _, full := hardLinks(home, "a"); full {
		t.Error("three files under a cap of 2 reported as checked in full")
	}
}
