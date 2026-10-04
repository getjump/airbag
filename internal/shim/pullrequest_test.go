package shim

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCaptureFreezesFileBodyAndCommit(t *testing.T) {
	ws := t.TempDir()
	for _, args := range [][]string{{"init", "-q", "-b", "work"}, {"-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "init", "--allow-empty"}} {
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", ws}, args...)...) //nolint:gosec // test-owned git fixture
		if data, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git: %s %v", data, err)
		}
	}
	path := filepath.Join(ws, "notes.md")
	if err := os.WriteFile(path, []byte("reviewed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"gh", "pr", "create", "--repo", "getjump/airbag", "--base", "main", "--head", "work", "--title", "Fix", "--body-file", "notes.md"}
	r, err := capturePullRequest(args, ws)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("later\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r.PullRequest.Body != "reviewed\n" || len(r.PullRequest.HeadCommit) != 40 {
		t.Fatal("capture followed mutable input")
	}
	args[len(args)-1] = ".env"
	if _, err := capturePullRequest(args, ws); err == nil {
		t.Fatal("opened a secret body file")
	}
	args[len(args)-1] = "."
	if _, err := capturePullRequest(args, ws); err == nil {
		t.Fatal("accepted a directory")
	}
}
