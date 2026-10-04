package sandbox

import (
	"slices"
	"testing"
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
