package apply

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The branch's HEAD is the agent's to write; only an object name gets
// through to git on the host, where anything else could be an option.
func TestAgentHeadIsAnObjectID(t *testing.T) {
	s, _ := undoSession(t)
	git := filepath.Join(s.WSBranch(), ".git")
	if err := os.MkdirAll(filepath.Join(git, "refs", "heads"), 0o755); err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("ab", 20)
	for _, c := range []struct {
		head, ref string
		ok        bool
	}{
		{sha + "\n", "", true},
		{"ref: refs/heads/main\n", sha + "\n", true},
		{"--output=/tmp/x\n", "", false},
		{"ref: refs/heads/main\n", "--output=/tmp/x\n", false},
		{strings.ToUpper(sha) + "\n", "", false},
		{sha[:39] + "\n", "", false},
	} {
		if err := os.WriteFile(filepath.Join(git, "HEAD"), []byte(c.head), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(git, "refs", "heads", "main"), []byte(c.ref), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := agentHead(s)
		if c.ok && (err != nil || got != sha) {
			t.Errorf("HEAD %q ref %q: %q, %v", c.head, c.ref, got, err)
		}
		if !c.ok && err == nil {
			t.Errorf("HEAD %q ref %q: accepted as %q", c.head, c.ref, got)
		}
	}
}
