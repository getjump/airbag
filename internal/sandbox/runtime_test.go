package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/session"
)

func TestOptionalBoundaryNeverFallsBack(t *testing.T) {
	for name, isolation := range map[string]string{"gvisor": "application-kernel", "microvm": "virtual-machine"} {
		b, err := SelectBackend(name, isolation)
		if runtime.GOOS != "linux" {
			if err == nil {
				t.Fatal("optional provider accepted on unsupported host")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if b.Name != name || b.Isolation != isolation || b.HomeBranch {
			t.Fatalf("wrong contract %+v", b)
		}
		if _, err := SelectBackend(name, "shared-kernel"); err == nil {
			t.Fatal("accepted incompatible isolation")
		}
		if got := b.ForRun(nil).Egress; got != EgressProxy {
			t.Fatalf("%s reports egress %s; it mounts no host socket", name, got)
		}
	}
}

func TestRuntimeRejectsUnsupportedProfileBeforeSession(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux profile")
	}
	root := t.TempDir()
	t.Setenv("AIRBAG_HOME", filepath.Join(root, "sessions"))
	workspace := t.TempDir()
	b, err := SelectBackend("gvisor", "any")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		home, nix bool
		forwards  int
		pol       policy.Policy
	}{{home: true}, {nix: true}, {forwards: 1}, {pol: policy.Policy{Hide: []string{"secret"}}}} {
		if _, err := PreflightRuntime(b, session.RuntimeConfig{}, workspace, tc.home, tc.nix, tc.forwards, &tc.pol); err == nil {
			t.Fatal("accepted unsupported profile")
		}
	}
	if err := os.WriteFile(filepath.Join(workspace, ".env"), []byte("benign canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PreflightRuntime(b, session.RuntimeConfig{}, workspace, false, false, 0, &policy.Policy{}); err == nil {
		t.Fatal("accepted unmediated secret")
	}
	if _, err := os.Stat(session.Root()); !os.IsNotExist(err) {
		t.Fatal("preflight created session data")
	}
}
