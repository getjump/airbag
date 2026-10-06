//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/session"
)

// A signal that would end airbag ends the staging instead: its context is
// cancelled with the signal as the cause, and the run's code is 128 plus
// the signal's, as a shell reports it.
func TestStageEndsOnASignal(t *testing.T) {
	ctx, done := stage()
	defer done()
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the staging went on past a SIGHUP")
	}
	err := staged(ctx)
	var e interrupted
	if !errors.As(err, &e) || e.sig != syscall.SIGHUP {
		t.Fatalf("the staging's cause: %v", err)
	}
	if code := exitCode(err); code != 128+int(syscall.SIGHUP) {
		t.Fatalf("an interrupted run's code: %d", code)
	}
	if code := exitCode(errors.New("other")); code != 1 {
		t.Fatalf("another failure's code: %d", code)
	}
}

// Interrupted, the copy of the branch stops and leaves nothing: no
// clone, and no mark that it was copied.
func TestInterruptedCopyLeavesNoBranch(t *testing.T) {
	t.Setenv("AIRBAG_HOME", filepath.Join(t.TempDir(), "sessions"))
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("user\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Backend: "gvisor", Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(interrupted{syscall.SIGINT})
	err = prepareRuntimeWorkspace(ctx, s)
	var e interrupted
	if !errors.As(err, &e) {
		t.Fatalf("an interrupted copy: %v", err)
	}
	if _, err := os.Lstat(s.CloneDir()); !os.IsNotExist(err) {
		t.Fatalf("an interrupted copy left the clone: %v", err)
	}
	if saved, err := session.Load(s.Dir); err != nil || saved.RuntimeCopied {
		t.Fatalf("an interrupted copy marked as copied: %v", err)
	}
}

// The provider takes the signals over: once it starts, the staging is
// over, and one that came before it starts nothing.
func TestProviderStartsOnlyAfterTheStaging(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(interrupted{syscall.SIGTERM})
	marker := filepath.Join(t.TempDir(), "ran")
	if _, err := executeProvider(ctx, sh, []string{"-c", "touch " + marker}); !errors.As(err, new(interrupted)) {
		t.Fatalf("the provider after an interrupted staging: %v", err)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal("the provider ran after the staging was interrupted")
	}
}
