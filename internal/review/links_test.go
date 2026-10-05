package review

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
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
