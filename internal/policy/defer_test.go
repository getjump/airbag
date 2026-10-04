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

// Credentials come from the user's own file only.
func TestCredentialsUserOnly(t *testing.T) {
	ws, home := t.TempDir(), t.TempDir()
	cfg := "credentials:\n  - name: github\n    hosts: [api.github.com]\n    source: env:GH_TOKEN\n    env: [GH_TOKEN]\n"
	_ = os.MkdirAll(filepath.Join(home, ".config", "airbag"), 0o755)
	_ = os.WriteFile(filepath.Join(home, ".config", "airbag", "airbag.yaml"), []byte(cfg), 0o644)
	p, err := Load(ws, home)
	if err != nil || len(p.Credentials) != 1 || p.Credentials[0].Name != "github" {
		t.Fatalf("%+v %v", p, err)
	}
	_ = os.WriteFile(filepath.Join(ws, "airbag.yaml"), []byte(strings.ReplaceAll(cfg, "github", "evil")), 0o644)
	if _, err := Load(ws, home); err == nil || !strings.Contains(err.Error(), "a repository must not decide") {
		t.Fatalf("a repository's credentials were accepted: %v", err)
	}
}

// Masking model requests is the user's choice: their own file turns it
// on; a repository's file can neither turn it on nor off.
func TestMaskModelRequestsUserOnly(t *testing.T) {
	ws, home := t.TempDir(), t.TempDir()
	user := filepath.Join(home, ".config", "airbag", "airbag.yaml")
	_ = os.MkdirAll(filepath.Dir(user), 0o755)
	if p, err := Load(ws, home); err != nil || p.MaskModelRequests {
		t.Fatalf("on without being asked: %+v %v", p, err)
	}
	_ = os.WriteFile(user, []byte("mask_model_requests: true\n"), 0o644)
	if p, err := Load(ws, home); err != nil || !p.MaskModelRequests {
		t.Fatalf("the user's file did not turn it on: %+v %v", p, err)
	}
	for _, v := range []string{"true", "false"} {
		_ = os.WriteFile(filepath.Join(ws, "airbag.yaml"), []byte("mask_model_requests: "+v+"\n"), 0o644)
		if _, err := Load(ws, home); err == nil || !strings.Contains(err.Error(), "mask_model_requests can only be set in "+user) {
			t.Fatalf("a repository's mask_model_requests: %s was accepted: %v", v, err)
		}
	}
}
