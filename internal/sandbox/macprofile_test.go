package sandbox

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/seatbelt"
	"github.com/getjump/airbag/internal/session"
)

func TestMacProfile(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	// The profile spells paths resolved (Seatbelt checks those): /var is
	// /private/var on macOS.
	realTemp := func() string {
		d, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	home, ws := realTemp(), realTemp()
	if err := os.MkdirAll(filepath.Join(ws, "apps", "web"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{".env", "apps/web/.env", "main.go"} {
		if err := os.WriteFile(filepath.Join(ws, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	proj, holes := ClaudeProjectState(ws, ws)
	for _, d := range []string{ws, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
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

func TestFollowCanonicalizesMissingTargetAncestors(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(alias, "not-yet", "memory")
	link := filepath.Join(root, "memory-link")
	if err := os.Symlink(missing, link); err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(canonical, "not-yet", "memory")
	for _, path := range []string{missing, link} {
		if got := follow(path); got != want {
			t.Errorf("follow(%q) = %q, want %q", path, got, want)
		}
	}
	// A dangling link on the way leads where the agent could make its
	// target: memory/ is denied there, not under the link's name.
	dangling := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(alias, "later"), dangling); err != nil {
		t.Fatal(err)
	}
	if got, want := follow(filepath.Join(dangling, "memory")), filepath.Join(canonical, "later", "memory"); got != want {
		t.Errorf("follow through a dangling link = %q, want %q", got, want)
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
	for _, d := range []string{ws, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
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
	// $HOME spelled through a link, as /var is for /private/var on macOS:
	// a memory link to a path that does not exist yet is denied where
	// it really will be.
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(t.TempDir(), home); err != nil {
		t.Fatal(err)
	}
	ws := t.TempDir()
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
	for _, d := range []string{ws, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
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
	for _, d := range []string{ws, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
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
	for _, d := range []string{ws, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
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
	for _, d := range []string{ws, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
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

// A passthrough that cannot be checked in full for hard links is denied
// whole: a file past the check may have another name.
func TestMacProfileUncheckedPassthroughReadOnly(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home, ws := t.TempDir(), t.TempDir()
	dir := filepath.Join(home, ".claude/projects/x")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"a.jsonl", "b.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	defer func(n int) { maxPassFiles = n }(maxPassFiles)
	maxPassFiles = 1
	for _, d := range []string{ws, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, Clone: true, Passthrough: []string{".claude/projects/x/"}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := macProfile(s, 51234, filepath.Join(s.Dir, "tmp"), filepath.Join(s.Dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	h, _ := filepath.EvalSymlinks(home)
	if !slices.Contains(p.NoWrite, filepath.Join(h, ".claude/projects/x")) {
		t.Errorf("an unchecked passthrough is not denied: %v", p.NoWrite)
	}
}

// A protected memory file with another name inside ~/.claude keeps
// ~/.claude read-only: a write through that name is not a write to the
// denied path.
func TestMacProfileHardLinkedMemoryKeepsStateReadOnly(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home, ws := t.TempDir(), t.TempDir()
	mem := filepath.Join(home, ".claude/projects/other/memory/MEMORY.md")
	if err := os.MkdirAll(filepath.Dir(mem), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".claude/debug"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mem, []byte("notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{ws, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := filepath.EvalSymlinks(home)
	profile := func() seatbelt.Profile {
		p, err := macProfile(s, 51234, filepath.Join(s.Dir, "tmp"), filepath.Join(s.Dir, "cache"))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := profile(); !slices.Contains(p.Write, filepath.Join(h, ".claude")) {
		t.Fatalf("~/.claude not writable without a link: %v", p.Write)
	}
	if err := os.Link(mem, filepath.Join(home, ".claude/debug/x")); err != nil {
		t.Fatal(err)
	}
	if p := profile(); slices.Contains(p.Write, filepath.Join(h, ".claude")) {
		t.Errorf("~/.claude writable with a hard-linked memory file: %v", p.Write)
	}
}

// stateWritable builds the macOS profile for a session over home and
// reports whether ~/.claude and ~/.codex are writable.
func stateWritable(t *testing.T, home string) (claude, codex bool) {
	t.Helper()
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: home, Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	p, err := macProfile(s, 51234, filepath.Join(s.Dir, "tmp"), filepath.Join(s.Dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	h, _ := filepath.EvalSymlinks(home)
	return slices.Contains(p.Write, filepath.Join(h, ".claude")), slices.Contains(p.Write, filepath.Join(h, ".codex"))
}

func writeFile(t *testing.T, p, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A file directly in ~/.claude/projects (a .DS_Store) holds no memory:
// it does not make the state directories read-only.
func TestMacProfileStrayFileInProjects(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".claude/projects/.DS_Store"), "x")
	if claude, codex := stateWritable(t, home); !claude || !codex {
		t.Errorf("state not writable with a file in projects/: claude %v, codex %v", claude, codex)
	}
}

// Each protected file with another name in a state directory keeps
// both state directories read-only: the other name may be in either.
func TestMacProfileHardLinkedProtectedKeepsStateReadOnly(t *testing.T) {
	for _, c := range []struct{ protected, other string }{
		{".claude/projects/other/memory/MEMORY.md", ".codex/log/x"},
		{".claude/settings.json", ".claude/debug/x"},
		{".codex/config.toml", ".codex/log/x"},
	} {
		t.Setenv("AIRBAG_HOME", t.TempDir())
		home := t.TempDir()
		writeFile(t, filepath.Join(home, c.protected), "x")
		if err := os.MkdirAll(filepath.Dir(filepath.Join(home, c.other)), 0o700); err != nil {
			t.Fatal(err)
		}
		if claude, codex := stateWritable(t, home); !claude || !codex {
			t.Fatalf("%s: state not writable without a link", c.protected)
		}
		if err := os.Link(filepath.Join(home, c.protected), filepath.Join(home, c.other)); err != nil {
			t.Fatal(err)
		}
		if claude, codex := stateWritable(t, home); claude || codex {
			t.Errorf("%s linked to %s: claude writable %v, codex writable %v", c.protected, c.other, claude, codex)
		}
	}
}

// A protected directory that is a link (a dotfiles hooks/) is checked
// where it leads.
func TestMacProfileLinkedProtectedDirIsChecked(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home := t.TempDir()
	hook := filepath.Join(home, "dotfiles/hooks/pre.sh")
	writeFile(t, hook, "x")
	if err := os.MkdirAll(filepath.Join(home, ".claude/debug"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "dotfiles/hooks"), filepath.Join(home, ".claude/hooks")); err != nil {
		t.Fatal(err)
	}
	if claude, _ := stateWritable(t, home); !claude {
		t.Fatal("~/.claude not writable without a hard link")
	}
	if err := os.Link(hook, filepath.Join(home, ".claude/debug/x")); err != nil {
		t.Fatal(err)
	}
	if claude, _ := stateWritable(t, home); claude {
		t.Error("~/.claude writable with a hard link into a linked hooks/")
	}
}

// A protected tree too large to check keeps the state read-only.
func TestMacProfileUncheckedProtectedKeepsStateReadOnly(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	defer func(n int) { maxPassFiles = n }(maxPassFiles)
	maxPassFiles = 1
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".claude/plugins/a"), "x")
	if claude, _ := stateWritable(t, home); !claude {
		t.Fatal("~/.claude not writable with one plugin file")
	}
	writeFile(t, filepath.Join(home, ".claude/plugins/b"), "x")
	if claude, codex := stateWritable(t, home); claude || codex {
		t.Errorf("state writable past the cap: claude %v, codex %v", claude, codex)
	}
}
