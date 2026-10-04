package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

func TestMacProfile(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home, ws := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "apps", "web"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{".env", "apps/web/.env", "main.go"} {
		if err := os.WriteFile(filepath.Join(ws, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, Clone: true, Hidden: DefaultHidden,
		HiddenHost: []string{"/var/lib/incus/unix.socket"}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := macProfile(s, 51234, filepath.Join(s.Dir, "tmp"), filepath.Join(s.Dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	text := p.String()
	has := func(rule, path string) bool {
		return strings.Contains(text, "("+rule+" (subpath \""+path+"\"))") || strings.Contains(text, "("+rule+" (literal \""+path+"\"))")
	}
	clone, _ := filepath.EvalSymlinks(s.CloneDir())
	if clone == "" {
		clone = s.CloneDir()
	}
	for _, c := range []struct {
		rule, path string
	}{
		{"allow file-write*", clone},
		{"allow file-write*", filepath.Join(home, ".claude")},
		{"allow file-write*", filepath.Join(home, ".claude.json")},
		{"deny file-write*", filepath.Join(home, ".claude/settings.json")},
		{"deny file-write*", filepath.Join(home, ".codex/config.toml")},
		{"deny file-read*", filepath.Join(home, ".ssh")},
		{"deny file-read*", filepath.Join(home, ".config/sops")},
		{"deny file-read*", "/var/lib/incus/unix.socket"},
		{"deny file-read*", filepath.Join(clone, ".env")},
		{"deny file-read*", filepath.Join(clone, "apps/web/.env")},
		{"deny file-read*", filepath.Join(ws, ".env")},
	} {
		if !has(c.rule, c.path) {
			t.Errorf("profile lacks (%s %s)", c.rule, c.path)
		}
	}
	if has("allow file-write*", ws) || has("allow file-write*", home) {
		t.Error("the real workspace or all of ~ is writable")
	}
	if strings.Contains(text, "main.go") {
		t.Error("an ordinary file is denied")
	}
	if !strings.Contains(text, `(remote ip "localhost:51234")`) || strings.Count(text, "network-outbound") != 2 {
		t.Errorf("network rules:\n%s", text)
	}
}
