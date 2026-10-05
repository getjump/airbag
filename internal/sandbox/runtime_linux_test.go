//go:build linux

package sandbox

import (
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
