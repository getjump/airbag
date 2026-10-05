//go:build linux

package sandbox

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/session"
)

// runsc, Firecracker and their tools get PATH and nothing else of airbag's
// environment.
func TestProviderEnvIsMinimal(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "benign-canary-0123456789")
	t.Setenv("PATH", "/usr/bin:/bin")
	if env := providerEnv(); len(env) != 1 || env[0] != "PATH=/usr/bin:/bin" {
		t.Fatalf("provider environment: %q", env)
	}
}

// mke2fs makes ext2 when it is run by its own name, which is where
// hostTool's resolved link leads on Debian and Ubuntu: the image must
// still be ext4.
func TestExt4ImageIsExt4(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AIRBAG_HOME", filepath.Join(t.TempDir(), "sessions"))
	mkfs, err := hostTool("mkfs.ext4", t.TempDir())
	if err != nil {
		t.Skipf("no mkfs.ext4: %v", err)
	}
	dumpe2fs, err := exec.LookPath("dumpe2fs")
	if err != nil {
		t.Skip("no dumpe2fs")
	}
	img := filepath.Join(t.TempDir(), "work.ext4")
	if err := ext4Image(mkfs, src, img, 16<<20); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), dumpe2fs, "-h", img).CombinedOutput() //nolint:gosec // the test's own image
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(string(out), "extent") || !strings.Contains(string(out), "has_journal") {
		t.Fatalf("%s made no ext4 image:\n%s", mkfs, out)
	}
}

// A branch copied again, after the last one was lost, is not complete
// until this copy is: a copy that fails leaves no mark behind.
func TestRecopyClearsTheMark(t *testing.T) {
	t.Setenv("AIRBAG_HOME", filepath.Join(t.TempDir(), "sessions"))
	ws := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(ws, "pipe"), 0o600); err != nil { // the host's copy refuses it
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Backend: "gvisor", Clone: true, RuntimeCopied: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareRuntimeWorkspace(s); err == nil {
		t.Fatal("copied a workspace with a FIFO")
	}
	saved, err := session.Load(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if saved.RuntimeCopied || saved.RuntimeBranchError() == nil {
		t.Fatalf("a failed copy kept the last one's mark: %+v", saved.Meta)
	}
}

// The runtime's root filesystem is staged by a GNU cp found on PATH
// outside the agent's files; another cp is refused before a session
// exists.
func TestRootfsCopierIsGNU(t *testing.T) {
	t.Setenv("AIRBAG_HOME", filepath.Join(t.TempDir(), "sessions"))
	ws := t.TempDir()
	if _, err := rootfsCopier(ws); err != nil {
		t.Skipf("no GNU cp here: %v", err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "cp"), []byte("#!/bin/sh\necho 'BusyBox v1.36.1 multi-call binary.'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	if cp, err := rootfsCopier(ws); err == nil {
		t.Fatalf("staged with %s, which is not GNU cp", cp)
	}
}

// cmd/airbag refuses the runtime policies on an optional runtime; Run
// does too, before anything is copied or started, for a session that
// asks for one anyway, and records it stopped.
func TestOptionalRunRefusesRuntimePolicies(t *testing.T) {
	t.Setenv("AIRBAG_HOME", filepath.Join(t.TempDir(), "sessions"))
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: t.TempDir(), Backend: "gvisor", Clone: true, ExecPolicy: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(s, nil, nil); err == nil || !strings.Contains(err.Error(), "runtime policy") {
		t.Fatalf("an optional runtime ran a session with a runtime policy: %v", err)
	}
	saved, err := session.Load(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Status != session.StatusStopped {
		t.Fatalf("the refused session is %s", saved.Status)
	}
	if _, err := os.Lstat(s.CloneDir()); !os.IsNotExist(err) {
		t.Fatalf("the workspace was copied first: %v", err)
	}
}

// Every signal the native runner forwards reaches the provider, which
// decides how to end, and airbag goes on to stop the session: one not
// taken would end airbag first (SIGQUIT would) and leave it running.
func TestProviderGetsTheSignals(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	for _, sig := range []string{"INT", "QUIT", "TERM", "HUP"} {
		script := "trap 'exit 7' " + sig + "; kill -" + sig + " $PPID; while :; do sleep 0.05; done"
		code, err := executeProvider(sh, []string{"-c", script})
		if err != nil || code != 7 {
			t.Errorf("SIG%s: code %d, %v", sig, code, err)
		}
	}
}

// A command a signal ended reports 128 plus the signal, as native does,
// not one status for every signal.
func TestExitStatusAsNative(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	for script, want := range map[string]int{"exit 3": 3, "kill -TERM $$": 143, "kill -KILL $$": 137, "kill -SEGV $$": 139} {
		code, ok := exitStatus(exec.CommandContext(t.Context(), sh, "-c", script).Run()) //nolint:gosec // a fixed test script
		if !ok || code != want {
			t.Errorf("%s: %d %v, want %d", script, code, ok, want)
		}
	}
	if _, ok := exitStatus(exec.CommandContext(t.Context(), filepath.Join(t.TempDir(), "missing")).Run()); ok { //nolint:gosec // a path that does not exist
		t.Error("a command that did not start has an exit status")
	}
}

// Firecracker exiting nonzero is a provider failure, not an agent that
// ran: the run gets an error, and the export it left is gone.
func TestFailedVMMIsAProviderFailure(t *testing.T) {
	listen := func() net.Listener {
		l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", filepath.Join(t.TempDir(), "s"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		return l
	}
	stage := filepath.Join(t.TempDir(), "export")
	if err := os.MkdirAll(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	code, err := vmmFailed(startImport(listen(), stage), 1, nil)
	if code != 1 || err == nil || !strings.Contains(err.Error(), "firecracker exited with status 1") {
		t.Fatalf("a failed VMM: %d %v", code, err)
	}
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("the export stage is left: %v", err)
	}
	cause := errors.New("start firecracker: no such file")
	if _, err := vmmFailed(startImport(listen(), filepath.Join(t.TempDir(), "export")), 1, cause); !errors.Is(err, cause) {
		t.Fatalf("the provider's own error is lost: %v", err)
	}
}
