//go:build linux

package sandbox

import (
	"context"
	"errors"
	"io"
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

// Interrupted, the copy of the branch returns without waiting for the
// exporter, whose read of the workspace (FUSE, NFS) can block.
func TestInterruptedCopyDoesNotWaitForTheExporter(t *testing.T) {
	t.Setenv("AIRBAG_HOME", filepath.Join(t.TempDir(), "sessions"))
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: t.TempDir(), Backend: "gvisor", Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	defer close(release)
	exportBranch = func(string, io.Writer, bool) (exportStats, error) {
		<-release // a read that does not return
		return exportStats{}, errors.New("released")
	}
	defer func() { exportBranch = exportWorkspace }()
	ctx, cancel := context.WithCancelCause(context.Background())
	time.AfterFunc(50*time.Millisecond, func() { cancel(interrupted{syscall.SIGINT}) })
	done := make(chan error, 1)
	go func() { done <- prepareRuntimeWorkspace(ctx, s) }()
	select {
	case err := <-done:
		if !errors.As(err, new(interrupted)) {
			t.Fatalf("an interrupted copy: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the interrupted copy waited for a blocked exporter")
	}
	if _, err := os.Lstat(s.CloneDir()); !os.IsNotExist(err) {
		t.Fatalf("an interrupted copy left the clone: %v", err)
	}
}

// A signal that reached the provider's own channel before it started is
// an interruption too: nothing starts.
func TestPendingCatchesASignalBeforeTheStart(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	if err := pending(context.Background(), sigs); err != nil {
		t.Fatalf("no signal: %v", err)
	}
	sigs <- syscall.SIGINT
	var e interrupted
	if err := pending(context.Background(), sigs); !errors.As(err, &e) || e.sig != syscall.SIGINT {
		t.Fatalf("a queued signal: %v", err)
	}
}
