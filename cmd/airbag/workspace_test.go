package main

import (
	"os"
	"path/filepath"
	"testing"
)

// $HOME as the workspace is refused however either is spelled: git names
// a repository's top with links resolved, so a repository at ~ where
// $HOME is reached through a link (/home leading to /var/home) differs
// from $HOME as a string.
func TestWholeHome(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(real, "proj"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ws, home string
		want     bool
	}{
		{real, link, true},
		{link, real, true},
		{link + "/", link, true},
		{"/", link, true},
		{filepath.Join(real, "proj"), link, false},
		{filepath.Join(link, "proj"), real, false},
	} {
		if got := wholeHome(c.ws, c.home); got != c.want {
			t.Errorf("wholeHome(%s, %s) = %v, want %v", c.ws, c.home, got, c.want)
		}
	}
}
