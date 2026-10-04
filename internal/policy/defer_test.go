package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPatternMatch(t *testing.T) {
	cases := []struct {
		pattern string
		argv    string
		want    bool
	}{
		{"gh pr create", "gh pr create --title x --body y", true},
		{"gh pr create", "gh -R o/r pr create", true},
		{"gh pr create", "gh pr list --search create", false},
		{"gh pr create", "gh pr view 12", false},
		{"gh pr create", "/usr/bin/gh pr create", false}, // a full path skips the shim
		{"npm publish", "npm --registry https://r.example publish", true},
		{"npm publish", "npm install", false},
		{"twine", "twine upload dist/x.whl", true},
		{"tool run", "tool -- run it", true},
		{"tool run", "tool --run", false},
	}
	for _, c := range cases {
		p, err := ParsePattern(c.pattern)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Match(strings.Fields(c.argv)); got != c.want {
			t.Errorf("%q on %q: %v, want %v", c.pattern, c.argv, got, c.want)
		}
	}
}

func TestPatternRefused(t *testing.T) {
	for _, s := range []string{"", "./deploy.sh", "/usr/bin/gh pr", "git push", "bash", "sh -c", "env", "gh --repo x"} {
		if _, err := ParsePattern(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestLoadDefer(t *testing.T) {
	ws, home := t.TempDir(), t.TempDir()
	_ = os.WriteFile(filepath.Join(ws, "airbag.yaml"), []byte("defer:\n  - gh pr create\n  - gh release create\n  - npm publish\n"), 0o644)
	p, err := Load(ws, home)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.DeferPrograms(); strings.Join(got, ",") != "gh,npm" {
		t.Fatalf("programs %v", got)
	}
	if got := p.Defers([]string{"gh", "release", "create", "v1"}); got != "gh release create" {
		t.Fatalf("defers %q", got)
	}
	if got := p.Defers([]string{"gh", "pr", "list"}); got != "" {
		t.Fatalf("a read deferred: %q", got)
	}
	_ = os.WriteFile(filepath.Join(ws, "airbag.yaml"), []byte("defer: [git push]\n"), 0o644)
	if _, err := Load(ws, home); err == nil || !strings.Contains(err.Error(), "git push already waits") {
		t.Fatalf("git accepted: %v", err)
	}
}
