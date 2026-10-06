//go:build linux

package sandbox

import (
	"archive/tar"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
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

// A copy that is interrupted, or fails, returns without waiting for the
// exporter, whose read of the workspace (FUSE, NFS) can block.
func TestCopyDoesNotWaitForABlockedExporter(t *testing.T) {
	for name, write := range map[string]func(io.Writer){
		"interrupted": func(io.Writer) {},
		"failed": func(w io.Writer) { // an entry the import refuses
			tw := tar.NewWriter(w)
			_ = tw.WriteHeader(&tar.Header{Name: "../out", Typeflag: tar.TypeReg, Mode: 0o600})
			_ = tw.Flush()
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("AIRBAG_HOME", filepath.Join(t.TempDir(), "sessions"))
			s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: t.TempDir(), Backend: "gvisor", Clone: true})
			if err != nil {
				t.Fatal(err)
			}
			release := make(chan struct{})
			defer close(release)
			exportBranch = func(_ string, w io.Writer, _ bool) (exportStats, error) {
				write(w)
				<-release // a read that does not return
				return exportStats{}, errors.New("released")
			}
			defer func() { exportBranch = exportWorkspace }()
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			if name == "interrupted" {
				defer time.AfterFunc(50*time.Millisecond, func() { cancel(interrupted{syscall.SIGINT}) }).Stop()
			}
			done := make(chan error, 1)
			go func() { done <- prepareRuntimeWorkspace(ctx, s) }()
			select {
			case err := <-done:
				if interrupt := errors.As(err, new(interrupted)); err == nil || interrupt != (name == "interrupted") {
					t.Fatalf("the copy: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the copy waited for a blocked exporter")
			}
			if _, err := os.Lstat(s.CloneDir()); !os.IsNotExist(err) {
				t.Fatalf("the copy left the clone: %v", err)
			}
		})
	}
}

// A signal that reached the provider's own channel before it started is
// an interruption too: nothing starts, and the run ends with the
// signal's code.
func TestProviderSignalBeforeTheStart(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip(err)
	}
	ctx, done := stage()
	defer done()
	st, _ := ctx.Value(stagingKey{}).(*staging)
	notifyProvider = func(c chan<- os.Signal, sigs ...os.Signal) {
		select {
		case <-st.quit:
			t.Error("the staging let its signals go before the provider registered its own")
		default:
		}
		signal.Notify(c, sigs...)
		c <- syscall.SIGINT // as one that comes right then
	}
	defer func() { notifyProvider = signal.Notify }()
	code, err := executeProvider(ctx, sh, []string{"-c", "exit 0"})
	var e interrupted
	if !errors.As(err, &e) || e.sig != syscall.SIGINT {
		t.Fatalf("the provider started past a signal: %d %v", code, err)
	}
	if code := failedCode(ctx, code, err); code != 128+int(syscall.SIGINT) {
		t.Fatalf("the run's code: %d", code)
	}
}

// A signal the staging got, but has not acted on when the provider takes
// the signals over, is its interruption still.
func TestHandOverKeepsAStagedSignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGHUP} {
		for range 200 {
			ctx, done := stage()
			st, _ := ctx.Value(stagingKey{}).(*staging)
			ch := st.hard
			if sig == syscall.SIGINT {
				ch = st.soft
			}
			ch <- sig // as package signal delivers it
			endStaging(ctx)
			err := staged(ctx)
			done()
			var e interrupted
			if !errors.As(err, &e) || e.sig != sig {
				t.Fatalf("%v before the hand-over: %v", sig, err)
			}
		}
	}
}

// After the first signal, a second Ctrl-C ends airbag, should the
// staging hang. A second hang-up, as a closed terminal sends, or kill
// does not: the run goes on to save its stop. After the provider has
// exited, none does, as with the native runner: a Ctrl-C that would have
// gone to the agent comes during the cleanup. Once the run has returned,
// each is airbag's own again.
func TestSignalsDuringAnOptionalRun(t *testing.T) {
	for _, c := range []struct {
		mode string
		sig  syscall.Signal
		ends bool
	}{
		{"staging", syscall.SIGINT, true},
		{"staging", syscall.SIGHUP, false},
		{"staging", syscall.SIGTERM, false},
		{"provider", syscall.SIGINT, false},
		{"provider", syscall.SIGHUP, false},
		{"provider", syscall.SIGTERM, false},
	} {
		t.Run(c.mode+"/"+c.sig.String(), func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestStagingSignalsHelper$") //nolint:gosec // this test binary, as the helper
			cmd.Env = append(os.Environ(), "AIRBAG_TEST_STAGING="+c.mode)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			lines := bufio.NewScanner(stdout)
			await := func(want string) bool {
				for lines.Scan() {
					if lines.Text() == want {
						return true
					}
				}
				return false
			}
			killedBy := func(sig syscall.Signal) bool {
				for lines.Scan() {
				}
				_ = cmd.Wait()
				ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
				return ws.Signaled() && ws.Signal() == sig
			}
			if !await("staging") {
				t.Fatal("the helper never staged")
			}
			if c.mode == "staging" {
				_ = cmd.Process.Signal(c.sig)
			}
			if !await("waiting") {
				t.Fatal("the helper never got to its cleanup")
			}
			_ = cmd.Process.Signal(c.sig)
			time.Sleep(200 * time.Millisecond)
			_ = stdin.Close()
			if c.ends {
				if !killedBy(c.sig) {
					t.Fatalf("a second %v did not end a hung staging", c.sig)
				}
				return
			}
			if !await("stopped") || !await("done") {
				_ = cmd.Wait()
				t.Fatalf("a %v ended the run before it saved its stop: %v", c.sig, cmd.ProcessState)
			}
			_ = cmd.Process.Signal(c.sig)
			if !killedBy(c.sig) {
				t.Fatalf("a %v after the run is still caught: %v", c.sig, cmd.ProcessState)
			}
		})
	}
}

func TestStagingSignalsHelper(t *testing.T) {
	mode := os.Getenv("AIRBAG_TEST_STAGING")
	if mode == "" {
		return
	}
	ctx, done := stage()
	fmt.Println("staging")
	switch mode {
	case "staging":
		<-ctx.Done()
	case "provider":
		if _, err := executeProvider(ctx, "/bin/sh", []string{"-c", "exit 0"}); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Println("waiting")
	_, _ = io.Copy(io.Discard, os.Stdin) // the run's cleanup, until the test lets it end
	fmt.Println("stopped")
	done()
	fmt.Println("done")
	time.Sleep(5 * time.Second) // for the test's signal
}
