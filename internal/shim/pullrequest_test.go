package shim

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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
	r, real, err := capturePullRequest(args, ws)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.EvalSymlinks(path); real != want {
		t.Fatalf("body pinned at %q, want %q", real, want)
	}
	if err := os.WriteFile(path, []byte("later\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r.PullRequest.Body != "reviewed\n" || len(r.PullRequest.HeadCommit) != 40 {
		t.Fatal("capture followed mutable input")
	}
	args[len(args)-1] = ".env"
	if _, _, err := capturePullRequest(args, ws); err == nil {
		t.Fatal("opened a secret body file")
	}
	args[len(args)-1] = "."
	if _, _, err := capturePullRequest(args, ws); err == nil {
		t.Fatal("accepted a directory")
	}
	// A benign name linked to a secret file is not read through.
	if err := os.WriteFile(filepath.Join(ws, ".env"), []byte("TOKEN=s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".env", filepath.Join(ws, "linked.md")); err != nil {
		t.Fatal(err)
	}
	args[len(args)-1] = "linked.md"
	if r, _, err := capturePullRequest(args, ws); err == nil {
		t.Fatalf("read a body through a link: %q", r.PullRequest.Body)
	}
	// Through a linked directory the body is pinned where it really
	// is, outside the workspace, so the host refuses the call.
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "notes.md"), []byte("elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, filepath.Join(ws, "docs")); err != nil {
		t.Fatal(err)
	}
	args[len(args)-1] = "docs/notes.md"
	_, real, err = capturePullRequest(args, ws)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.EvalSymlinks(filepath.Join(out, "notes.md")); real != want {
		t.Fatalf("body through a linked directory pinned at %q, want %q", real, want)
	}
}

// A FIFO as the body is refused at once, not waited on for a writer.
func TestCaptureRefusesFIFO(t *testing.T) {
	ws := t.TempDir()
	for _, args := range [][]string{{"init", "-q", "-b", "work"}, {"-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "init", "--allow-empty"}} {
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", ws}, args...)...) //nolint:gosec // test-owned git fixture
		if data, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git: %s %v", data, err)
		}
	}
	if err := unix.Mkfifo(filepath.Join(ws, "body.md"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := capturePullRequest([]string{"gh", "pr", "create", "--repo", "getjump/airbag", "--base", "main", "--head", "work", "--title", "Fix", "--body-file", "body.md"}, ws)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("captured a FIFO as the body")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waited on a FIFO for a writer")
	}
}
