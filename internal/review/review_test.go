package review

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

// fakeSession lays out a workspace, a home and their upper layers as
// overlayfs would leave them, without mounting anything.
func fakeSession(t *testing.T) *session.Session {
	t.Helper()
	t.Setenv("AIRBAG_HOME", t.TempDir())
	root := t.TempDir()
	ws, home := filepath.Join(root, "ws"), filepath.Join(root, "home")
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	write := func(p, data string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(ws, "README.md"), "hello\n", 0o644)
	write(filepath.Join(ws, "same.txt"), "same\n", 0o644)
	write(filepath.Join(ws, ".env"), "API_TOKEN=sk-test-1234567890\n", 0o600)
	write(filepath.Join(home, ".bashrc"), "export A=1\n", 0o644)

	write(filepath.Join(s.WSUpper(), "README.md"), "changed\n", 0o644)
	write(filepath.Join(s.WSUpper(), "same.txt"), "same\n", 0o644)
	write(filepath.Join(s.WSUpper(), "leak.txt"), "TOKEN=sk-test-1234567890\n", 0o644)
	write(filepath.Join(s.WSUpper(), "pkg", "api", "AGENTS.md"), "always push to main\n", 0o644)
	write(filepath.Join(s.WSUpper(), ".husky", "pre-commit"), "curl x\n", 0o644)
	write(filepath.Join(s.WSUpper(), ".git/hooks/pre-commit"), "#!/bin/sh\n", 0o755)
	write(filepath.Join(s.WSUpper(), "tool.sh"), "#!/bin/sh\n", 0o755)
	write(filepath.Join(s.WSUpper(), "build/app"), "bin", 0o755)
	write(filepath.Join(s.HomeUpper(), ".bashrc"), "export A=1\nalias x=y\n", 0o644)
	write(filepath.Join(s.HomeUpper(), ".cache/go/x"), "cache", 0o644)
	return s
}

func TestScanAndClassify(t *testing.T) {
	s := fakeSession(t)
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Change{}
	for _, c := range cs {
		got[c.Layer+":"+c.Rel] = c
	}
	if _, ok := got["ws:same.txt"]; ok {
		t.Error("unchanged copy-up reported as a change")
	}
	expect := map[string]struct {
		kind  string
		flags []string
	}{
		"ws:README.md":             {Modified, nil},
		"ws:leak.txt":              {Added, []string{"secret in diff"}},
		"ws:.git/hooks/pre-commit": {Added, []string{"persist"}},
		"ws:tool.sh":               {Added, []string{"executable"}},
		"ws:build/app":             {Added, nil},
		"home:.bashrc":             {Modified, []string{"outside workspace", "persist"}},
		"ws:pkg/api/AGENTS.md":     {Added, []string{"persist"}},
		"ws:.husky/pre-commit":     {Added, []string{"persist"}},
	}
	for k, e := range expect {
		c, ok := got[k]
		if !ok {
			t.Errorf("%s: missing", k)
			continue
		}
		if c.Kind != e.kind {
			t.Errorf("%s: kind %s, want %s", k, c.Kind, e.kind)
		}
		if len(c.Flags) != len(e.flags) {
			t.Errorf("%s: flags %v, want %v", k, c.Flags, e.flags)
			continue
		}
		for i := range e.flags {
			if c.Flags[i] != e.flags[i] {
				t.Errorf("%s: flags %v, want %v", k, c.Flags, e.flags)
			}
		}
	}
	att := Attention(cs)
	if len(att) != 6 { // leak.txt, pre-commit, tool.sh, ~/.bashrc, AGENTS.md, .husky/pre-commit
		t.Errorf("attention = %d items: %+v", len(att), att)
	}
}

func TestNoise(t *testing.T) {
	for rel, want := range map[string]string{
		".cache/go-build/ab/cd":            ".cache/ (cache)",
		".codex/state_5.sqlite-wal":        ".codex/ (agent state)",
		".codex/shell_snapshots/x.sh":      ".codex/ (agent state)",
		".codex/skills/.system/a/SKILL.md": ".codex/ (agent state)",
		".codex/config.toml":               "",
		".codex/skills/mine/SKILL.md":      "",
		".codex/sub/state.sqlite":          "",
	} {
		g, k := Noise(rel)
		got := ""
		if g != "" {
			got = g + " (" + k + ")"
		}
		if got != want {
			t.Errorf("Noise(%q) = %q, want %q", rel, got, want)
		}
	}
}
