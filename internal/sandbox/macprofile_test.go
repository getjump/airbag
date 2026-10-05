package sandbox

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	proj, holes := ClaudeProjectState(ws, ws)
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, Clone: true, Hidden: DefaultHidden,
		HiddenHost:  []string{"/var/lib/incus/unix.socket"},
		Passthrough: append(append([]string{}, DefaultPassthrough...), proj...), BranchHoles: holes})
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
	for _, re := range []string{`/\.claude/projects/[^/]+/memory(/|$)"))`, `/\.(claude|codex)$"))`, `/\.claude/projects(/[^/]+)?$"))`} {
		if !strings.Contains(text, re) {
			t.Errorf("profile lacks the write deny %s", re)
		}
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
		{"allow file-write*", filepath.Join(home, ".claude/projects/"+ClaudeProjectSlug(ws))},
		{"deny file-write*", filepath.Join(home, ".claude/projects/"+ClaudeProjectSlug(ws)+"/memory")},
		{"deny file-write*", filepath.Join(home, ".claude/settings.json")},
		{"deny file-write*", filepath.Join(home, ".claude/rules")},
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

func TestMacHomesHidden(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"alice/.ssh", "Shared", "bob"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := strings.Join(MacHomesHidden([]string{root, filepath.Join(root, "missing")}), "\n")
	for _, want := range []string{"alice/.ssh", "bob/.aws", "alice/Library/Keychains", "bob/Library/Application Support/sops"} {
		if !strings.Contains(got, filepath.Join(root, want)) {
			t.Errorf("lacks %s", want)
		}
	}
	if strings.Contains(got, "Shared") {
		t.Error("/Users/Shared is not a home")
	}
}

// A ~/.claude that is a symlink: building the profile creates nothing
// behind it (no project directory, no memory/ hole).
func TestMacProfileNoMkdirThroughSymlink(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home, ws, outside := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	proj, holes := ClaudeProjectState(ws, ws)
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, Clone: true,
		Passthrough: append(append([]string{}, DefaultPassthrough...), proj...), BranchHoles: holes})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := macProfile(s, 51234, filepath.Join(s.Dir, "tmp"), filepath.Join(s.Dir, "cache")); err != nil {
		t.Fatal(err)
	}
	if es, _ := os.ReadDir(outside); len(es) != 0 {
		t.Fatalf("created behind the symlinked ~/.claude: %v", es)
	}
}

// A project's memory/ linked elsewhere in ~/.claude is denied where it
// really is, and so are the directories above it, whether the link
// target exists yet or not.
func TestMacProfileDeniesLinkedMemory(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home, ws := t.TempDir(), t.TempDir()
	for _, d := range []string{".claude/shared/mem", ".claude/projects/a", ".claude/projects/b", ".claude/elsewhere"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../../shared/mem", filepath.Join(home, ".claude/projects/a/memory")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".claude/later/mem"), filepath.Join(home, ".claude/projects/b/memory")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".claude/elsewhere"), filepath.Join(home, ".claude/projects/c")); err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	p, err := macProfile(s, 51234, filepath.Join(s.Dir, "tmp"), filepath.Join(s.Dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	h, _ := filepath.EvalSymlinks(home)
	for _, want := range []string{"shared/mem", "later/mem", "elsewhere/memory"} {
		if !slices.Contains(p.NoWrite, filepath.Join(h, ".claude", want)) {
			t.Errorf("%s not denied: %v", want, p.NoWrite)
		}
	}
	for _, d := range []string{"shared", "later"} {
		if !slices.Contains(p.NoWriteRegex, "^"+regexp.QuoteMeta(filepath.Join(h, ".claude", d))+"$") {
			t.Errorf("%s may be renamed: %v", d, p.NoWriteRegex)
		}
	}
}
