package sandbox

import (
	"slices"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

func TestClaudeProjectSlug(t *testing.T) {
	if got := ClaudeProjectSlug("/home/me/src/api"); got != "-home-me-src-api" {
		t.Errorf("slug = %q", got)
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
