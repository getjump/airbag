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

// A project's memory/ linked elsewhere in ~/.claude, or under a linked
// project directory, is denied where it really is, and so are the
// directories above it, whether the link target exists yet or not.
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
	if err := os.Symlink("../not-yet", filepath.Join(home, ".claude/projects/d")); err != nil {
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
	for _, want := range []string{"shared/mem", "later/mem", "elsewhere/memory", "not-yet/memory"} {
		if !slices.Contains(p.NoWrite, filepath.Join(h, ".claude", want)) {
			t.Errorf("%s not denied: %v", want, p.NoWrite)
		}
	}
	for _, d := range []string{"shared", "later", "not-yet"} {
		if !slices.Contains(p.NoWriteRegex, "^"+regexp.QuoteMeta(filepath.Join(h, ".claude", d))+"$") {
			t.Errorf("%s may be renamed: %v", d, p.NoWriteRegex)
		}
	}
}

// A ~/.claude/projects that is a link elsewhere in ~/.claude gets the
// patterns where it really is, so a project made during the run cannot
// have a memory/ either.
func TestMacProfileDeniesLinkedProjectsRoot(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home, ws := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude/store/projects"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("store/projects", filepath.Join(home, ".claude/projects")); err != nil {
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
	real := filepath.Join(h, ".claude/store/projects")
	match := func(path string) bool {
		for _, re := range p.NoWriteRegex {
			if regexp.MustCompile(re).MatchString(path) {
				return true
			}
		}
		return false
	}
	for _, path := range []string{real + "/new-slug/memory/MEMORY.md", real + "/new-slug", real, filepath.Join(h, ".claude/store")} {
		if !match(path) {
			t.Errorf("%s may be written: %v", path, p.NoWriteRegex)
		}
	}
	if match(real + "/new-slug/transcript.jsonl") {
		t.Errorf("a transcript is denied")
	}
}

// A read-only state path that is a link elsewhere in ~/.claude is
// denied where it really is, whether that exists yet or not.
func TestMacProfileDeniesLinkedReadOnlyState(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home, ws := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude/shared-rules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("shared-rules", filepath.Join(home, ".claude/rules")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../dotfiles/settings.json", filepath.Join(home, ".claude/settings.json")); err != nil {
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
	for _, want := range []string{filepath.Join(h, ".claude/shared-rules"), filepath.Join(h, "dotfiles/settings.json")} {
		if !slices.Contains(p.NoWrite, want) {
			t.Errorf("%s not denied: %v", want, p.NoWrite)
		}
	}
	if !slices.Contains(p.NoWriteRegex, "^"+regexp.QuoteMeta(filepath.Join(h, "dotfiles"))+"$") {
		t.Errorf("dotfiles/ may be renamed: %v", p.NoWriteRegex)
	}
}

// A passed-through file with another hard-linked name stays read-only:
// Seatbelt would let a write through this name reach the other.
func TestMacProfileHardLinkedPassthroughReadOnly(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home, ws := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte("# rc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(home, ".bashrc"), filepath.Join(home, ".claude/.credentials.json")); err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, Clone: true, Passthrough: []string{".claude/.credentials.json"}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := macProfile(s, 51234, filepath.Join(s.Dir, "tmp"), filepath.Join(s.Dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	h, _ := filepath.EvalSymlinks(home)
	if !slices.Contains(p.NoWrite, filepath.Join(h, ".claude/.credentials.json")) {
		t.Errorf("the hard-linked passthrough is not denied: %v", p.NoWrite)
	}
}
