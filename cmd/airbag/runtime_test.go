//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/apply"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/review"
	"github.com/getjump/airbag/internal/sandbox"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/outbox"
	"github.com/getjump/airbag/proxy"
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
	if _, err := os.Stat(filepath.Join(s.Dir, "runtime")); !os.IsNotExist(err) {
		t.Fatalf("the runtime directory outlived the run: %v", err)
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

// linkedRuntimeSession is a gVisor session of a workspace named through a
// symlink, after a run that copied the branch and then failed (its rootfs
// is gone). real holds keep.txt and sub/gone.txt.
func linkedRuntimeSession(t *testing.T) (s *session.Session, real string) {
	t.Helper()
	t.Setenv("AIRBAG_HOME", filepath.Join(t.TempDir(), "s"))
	dir := t.TempDir()
	real, ws := filepath.Join(dir, "real"), filepath.Join(dir, "ws")
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"keep.txt", "sub/gone.txt"} {
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
	if _, err := sandbox.Run(s, proxy.Allowlist(nil), &policy.Policy{}); err == nil {
		t.Fatal("a run without its rootfs succeeded")
	}
	return s, real
}

// A file the guest deleted shows as Deleted through a symlinked workspace,
// named by the workspace's path, and only that file; apply removes it from
// the real tree and nothing else.
func TestRuntimeDeletionThroughLinkedWorkspace(t *testing.T) {
	s, real := linkedRuntimeSession(t)
	if err := os.Remove(filepath.Join(s.CloneDir(), "sub", "gone.txt")); err != nil { // as the guest's export would lack it
		t.Fatal(err)
	}
	cs, err := review.Scan(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].Kind != review.Deleted || cs[0].Rel != filepath.Join("sub", "gone.txt") ||
		cs[0].Path != filepath.Join(s.Workspace, "sub", "gone.txt") {
		t.Fatalf("review through the link: %+v", cs)
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer box.Close()
	var out bytes.Buffer
	if err := apply.Apply(s, cs, box, apply.Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if _, err := os.Stat(filepath.Join(real, "sub", "gone.txt")); !os.IsNotExist(err) {
		t.Fatalf("apply left the deleted file: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(real, "keep.txt")); err != nil || string(b) != "keep.txt" {
		t.Fatalf("apply touched another file: %q %v", b, err)
	}
}

// A session without a complete branch has nothing to review or apply:
// compared with the real files, every file it lacks would show as deleted,
// and apply would remove it. Resume copies a missing branch again (no agent
// ran on it, or it is gone either way) and refuses an unmarked one, which
// may hold the agent's work. Discard works, and the real files stay.
func TestIncompleteRuntimeBranchIsRefused(t *testing.T) {
	for _, c := range []struct {
		name     string
		copied   bool // RuntimeCopied after breaking
		clone    bool // an (empty) clone directory is left
		resumes  bool
		scanSays string
	}{
		{"copy failed", false, false, true, "no complete branch"},
		{"older airbag, empty", false, true, false, "no complete branch"},
		{"branch lost", true, false, true, "lost its branch"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, real := linkedRuntimeSession(t)
			s.RuntimeCopied = c.copied
			if err := os.RemoveAll(s.CloneDir()); err != nil {
				t.Fatal(err)
			}
			if c.clone {
				if err := os.Mkdir(s.CloneDir(), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Save(); err != nil {
				t.Fatal(err)
			}
			saved, err := session.Find(s.ID, s.Workspace)
			if err != nil {
				t.Fatal(err)
			}
			if cs, err := review.Scan(saved); err == nil || !strings.Contains(err.Error(), c.scanSays) {
				t.Fatalf("review of a branch that is not complete: %d changes, %v", len(cs), err)
			}
			box, err := outbox.Open(saved.EffectsPath())
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err = apply.Apply(saved, nil, box, apply.Options{Yes: true, Force: true, Out: &out})
			_ = box.Close()
			if err == nil {
				t.Fatal("apply ran on a branch that is not complete")
			}
			_, err = sandbox.Run(saved, proxy.Allowlist(nil), &policy.Policy{}) // fails later either way: no rootfs
			switch {
			case c.resumes && (!saved.RuntimeCopied || strings.Contains(err.Error(), "no complete branch")):
				t.Fatalf("resume did not copy the branch again: %v", err)
			case !c.resumes && (err == nil || !strings.Contains(err.Error(), "no complete branch")):
				t.Fatalf("resume of an unmarked branch: %v", err)
			}
			if err := cmdDiscard([]string{s.ID, "--yes"}); err != nil {
				t.Fatalf("discard: %v", err)
			}
			for _, f := range []string{"keep.txt", "sub/gone.txt"} {
				if b, err := os.ReadFile(filepath.Join(real, f)); err != nil || string(b) != f {
					t.Fatalf("the real %s changed: %q %v", f, b, err)
				}
			}
		})
	}
}
