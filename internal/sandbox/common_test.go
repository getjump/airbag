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
