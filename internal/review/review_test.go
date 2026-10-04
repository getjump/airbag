package review

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/outbox"
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
	write(filepath.Join(ws, "deploy", "prod", ".env.production"), "DB_PASSWORD='deep-secret-value'\n", 0o600)
	write(filepath.Join(s.WSUpper(), "docs", "notes.md"), "db pass is deep-secret-value\n", 0o644)
	write(filepath.Join(s.HomeUpper(), ".local/share/systemd/user/sync.service"), "[Service]\nExecStart=/bin/true\n", 0o644)
	write(filepath.Join(s.HomeUpper(), ".local/lib/python3.12/site-packages/zz.pth"), "import os\n", 0o644)
	write(filepath.Join(s.HomeUpper(), ".local/share/recently-used.xbel"), "x", 0o644)
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
		"ws:docs/notes.md":         {Added, []string{"secret in diff"}},
		"home:.local/share/systemd/user/sync.service":     {Added, []string{"outside workspace", "persist"}},
		"home:.local/lib/python3.12/site-packages/zz.pth": {Added, []string{"outside workspace", "persist"}},
		"home:.local/share/recently-used.xbel":            {Added, []string{"outside workspace"}},
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
	if len(att) != 9 { // leak.txt, pre-commit, tool.sh, ~/.bashrc, AGENTS.md, .husky/pre-commit, notes.md, sync.service, zz.pth
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

func TestPersistTable(t *testing.T) {
	for rel, want := range map[string]bool{
		".bash_login": true, ".zlogin": true, ".config/environment.d/10-x.conf": true,
		".local/share/dbus-1/services/x.service": true, ".local/share/applications/x.desktop": true,
		".config/niri/config.kdl": true, ".gradle/init.d/x.gradle": true, ".cargo/config.toml": true,
		".claude.json": true, ".claude.json.backup": false, ".local/share/fonts/a.ttf": false,
		".local/lib/python3.12/site-packages/pkg/__init__.py": false, ".config/systemd": true,
	} {
		if got := persistReason(rel, persistHomeTable) != ""; got != want {
			t.Errorf("home %s: persist %v, want %v", rel, got, want)
		}
	}
	for rel, want := range map[string]bool{
		".gitmodules": true, ".pnpmfile.cjs": true, ".mvn/extensions.xml": true,
		".vscode/settings.json": true, ".vscode/extensions.json": false, "src/main.go": false,
	} {
		if got := persistReason(rel, persistWSTable) != ""; got != want {
			t.Errorf("ws %s: persist %v, want %v", rel, got, want)
		}
	}
}

func TestReport(t *testing.T) {
	s := fakeSession(t)
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	effs := []effects.Effect{
		{Kind: "net.egress", Target: "api.anthropic.com:443", Verdict: "allow"},
		{Kind: "net.egress", Target: "paste.example.net:443", Verdict: "deny", Reason: "host not in allowlist"},
		{Kind: "secret.read", Target: ".env", Verdict: "taint", Reason: "/usr/bin/cat"},
		{Kind: "tool.call", Target: "Bash: rm -rf /", Verdict: "deny", Reason: "no-rm"},
	}
	intents := []outbox.Intent{{ID: "i-1", Argv: []string{"git", "push", "origin", "main"}, Status: outbox.Pending}}
	r := BuildReport(s, cs, effs, intents, nil)
	if r.Schema != Schema || r.Network.Allowed["api.anthropic.com"] != 1 || r.Network.Denied["paste.example.net:443"] != 1 {
		t.Fatalf("report %+v", r)
	}
	var whats []string
	for _, a := range r.Attention {
		whats = append(whats, a.What+":"+a.Target)
	}
	got := strings.Join(whats, " ")
	for _, want := range []string{"secret:.env", "change:.git/hooks/pre-commit", "change:~/.bashrc", "intent:i-1", "blocked:Bash: rm -rf /"} {
		if !strings.Contains(got, want) {
			t.Errorf("attention lacks %s: %s", want, got)
		}
	}
	if !strings.HasPrefix(got, "secret:") || !strings.HasSuffix(got, "blocked:Bash: rm -rf /") {
		t.Errorf("attention order: %s", got)
	}
	var b strings.Builder
	if err := WriteJSON(&b, r); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(b.String()), &back); err != nil || back["schema"] != Schema {
		t.Fatalf("JSON round trip: %v", err)
	}
	for _, k := range []string{"changes", "attention", "network", "secrets_read", "untrusted_from", "packages", "blocked", "outbox", "steps"} {
		if _, ok := back[k]; !ok {
			t.Errorf("JSON lacks %s", k)
		}
	}
}
