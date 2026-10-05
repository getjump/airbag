//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/proxy"
	"github.com/getjump/airbag/internal/review"
	"github.com/getjump/airbag/internal/sandbox"
	"github.com/getjump/airbag/internal/session"
)

// An optional runtime that fails after the session exists (here staging a
// rootfs that is gone) leaves the session stopped, so it can be reviewed
// and discarded. The workspace is reached through a symlink, as a non-git
// cwd can be: the branch holds its files, so review shows no deletion.
func TestFailedRuntimeRunStops(t *testing.T) {
	t.Setenv("AIRBAG_HOME", filepath.Join(t.TempDir(), "s"))
	dir := t.TempDir()
	real, ws := filepath.Join(dir, "real"), filepath.Join(dir, "ws")
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"keep.txt", "sub/nested.txt"} {
		if err := os.WriteFile(filepath.Join(real, f), []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("real", ws); err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{
		Backend: "gvisor", Isolation: "application-kernel", RequireIsolation: "any", Egress: sandbox.EgressProxy,
		Workspace: ws, Home: t.TempDir(), Clone: true, UID: os.Getuid(), GID: os.Getgid(), Argv: []string{"true"}, Cwd: ws,
		HiddenHost: sandbox.HostSockets,
		Runtime:    session.RuntimeConfig{RootFS: filepath.Join(dir, "gone"), Binary: "/bin/false"},
	})
	if err != nil {
		t.Fatal(err)
	}
	code, err := sandbox.Run(s, proxy.Allowlist(nil), &policy.Policy{})
	if err == nil || code == 0 {
		t.Fatalf("a run without its rootfs succeeded: code=%d err=%v", code, err)
	}
	saved, err := session.Find(s.ID, ws)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Status != session.StatusStopped || saved.ExitCode == 0 {
		t.Fatalf("failed run left status %q, exit %d", saved.Status, saved.ExitCode)
	}
	for _, f := range []string{"keep.txt", "sub/nested.txt"} {
		if _, err := os.Stat(filepath.Join(saved.CloneDir(), f)); err != nil {
			t.Fatalf("the branch lacks %s: %v", f, err)
		}
	}
	cs, err := review.Scan(saved)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Kind == review.Deleted {
			t.Fatalf("review shows a real file deleted: %+v", c)
		}
	}
	if err := cmdDiscard([]string{s.ID, "--yes"}); err != nil {
		t.Fatalf("discard refused the failed session: %v", err)
	}
	if _, err := os.Stat(s.Dir); !os.IsNotExist(err) {
		t.Fatalf("discard left the session: %v", err)
	}
	for _, f := range []string{"keep.txt", "sub/nested.txt"} {
		if b, err := os.ReadFile(filepath.Join(real, f)); err != nil || string(b) != f {
			t.Fatalf("the real %s changed: %q %v", f, b, err)
		}
	}
}
