package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
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
		for _, l := range sharedLimitations {
			if !slices.Contains(b.Limitations, l) {
				t.Fatalf("%s drops the shared limit %q", name, l)
			}
		}
		// No host socket is mounted, and preflight refuses --nix-daemon and
		// forwards: whatever the session's fields say, egress is the proxy's.
		if got := b.ForRun(nil, []session.Forward{{Host: "db.internal", Port: 5432}}).Egress; got != EgressProxy {
			t.Fatalf("%s reports egress %s; it mounts no host socket and dials no forward", name, got)
		}
		if slices.ContainsFunc(b.Limitations, func(l string) bool { return strings.Contains(l, "such a session records egress") }) {
			t.Fatalf("%s lists a path around the proxy it refuses: %q", name, b.Limitations)
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
	// The same secret through a symlinked workspace, as a non-git cwd
	// reaches it: the copy follows the link, so the check must too.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(workspace, link); err != nil {
		t.Fatal(err)
	}
	if _, err := PreflightRuntime(b, session.RuntimeConfig{}, link, false, false, 0, &policy.Policy{}); err == nil || !strings.Contains(err.Error(), ".env") {
		t.Fatalf("a secret behind a symlinked workspace passed preflight: %v", err)
	}
}

// A tool found on PATH runs on this machine, so one in the workspace or
// the sessions, directly or through a link, is refused.
func TestHostToolComesFromOutside(t *testing.T) {
	t.Setenv("AIRBAG_HOME", filepath.Join(t.TempDir(), "sessions"))
	workspace := t.TempDir()
	tool := func(dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "image-tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(t.TempDir(), "bin")
	if err := os.Symlink(filepath.Join(workspace, "bin"), link); err != nil {
		t.Fatal(err)
	}
	wsLink := filepath.Join(t.TempDir(), "ws")
	if err := os.Symlink(workspace, wsLink); err != nil {
		t.Fatal(err)
	}
	tool(filepath.Join(workspace, "bin"))
	tool(filepath.Join(session.Root(), "bin"))
	outside := t.TempDir()
	tool(outside)
	for name, tc := range map[string]struct{ path, workspace string }{
		"workspace":        {filepath.Join(workspace, "bin"), workspace},
		"through a link":   {link, workspace},
		"linked workspace": {filepath.Join(workspace, "bin"), wsLink},
		"sessions":         {filepath.Join(session.Root(), "bin"), workspace},
	} {
		t.Setenv("PATH", tc.path+string(os.PathListSeparator)+outside)
		if p, err := hostTool("image-tool", tc.workspace); err == nil {
			t.Fatalf("%s: ran %s from the agent's files", name, p)
		}
	}
	t.Setenv("PATH", outside)
	p, err := hostTool("image-tool", workspace)
	if want, _ := filepath.EvalSymlinks(filepath.Join(outside, "image-tool")); err != nil || p != want {
		t.Fatalf("the tool from outside: %q %v", p, err)
	}
}

// The runtime binary and kernel come from outside the workspace and the
// sessions too.
func TestRuntimeFilesComeFromOutside(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux profile")
	}
	t.Setenv("AIRBAG_HOME", filepath.Join(t.TempDir(), "sessions"))
	workspace, rootfs := t.TempDir(), t.TempDir()
	bin := filepath.Join(workspace, "runsc")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := SelectBackend("gvisor", "any")
	if err != nil {
		t.Fatal(err)
	}
	_, err = PreflightRuntime(b, session.RuntimeConfig{RootFS: rootfs, Binary: bin}, workspace, false, false, 0, &policy.Policy{})
	if err == nil || !strings.Contains(err.Error(), "inside the workspace") {
		t.Fatalf("a runtime binary in the workspace passed preflight: %v", err)
	}
}

// runsc runs the sidecars in gvisor-bin next to it on the host: a
// gvisor-bin that is, or holds, a link into the workspace or the sessions
// is refused before a session exists.
func TestGVisorSidecarsComeFromOutside(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux profile")
	}
	sessions := filepath.Join(t.TempDir(), "sessions")
	t.Setenv("AIRBAG_HOME", sessions)
	workspace, rootfs := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, "tools", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "tools", "sub", "gofer"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sessions, "s-x"), 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := SelectBackend("gvisor", "any")
	if err != nil {
		t.Fatal(err)
	}
	for name, sidecars := range map[string]func(dir string){
		"a link into the workspace": func(dir string) {
			if err := os.Symlink(filepath.Join(workspace, "tools"), dir); err != nil {
				t.Fatal(err)
			}
		},
		"a file linked into the workspace": func(dir string) {
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(workspace, "tools", "sub", "gofer"), filepath.Join(dir, "gofer")); err != nil {
				t.Fatal(err)
			}
		},
		"a directory outside that links into the sessions": func(dir string) {
			between := t.TempDir()
			if err := os.Symlink(filepath.Join(sessions, "s-x"), filepath.Join(between, "deeper")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(between, filepath.Join(dir, "lib")); err != nil {
				t.Fatal(err)
			}
		},
		"a link to nothing": func(dir string) {
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(t.TempDir(), "gone"), filepath.Join(dir, "gofer")); err != nil {
				t.Fatal(err)
			}
		},
		// Into a session not made yet: the link leads nowhere now, and
		// into the agent's files once the session exists.
		"gvisor-bin itself a link to nothing": func(dir string) {
			if err := os.Symlink(filepath.Join(sessions, "s-later", "ws", "clone", "tools"), dir); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "runsc")
			if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			sidecars(filepath.Join(filepath.Dir(bin), "gvisor-bin"))
			_, err := PreflightRuntime(b, session.RuntimeConfig{RootFS: rootfs, Binary: bin}, workspace, false, false, 0, &policy.Policy{})
			if err == nil || !strings.Contains(err.Error(), "runsc's sidecars") {
				t.Fatalf("preflight: %v", err)
			}
			if strings.Contains(name, "link to nothing") && !strings.Contains(err.Error(), "is a link to nothing") {
				t.Fatalf("a dangling link refused for another reason: %v", err)
			}
		})
	}
	// No sidecars at all, and sidecars of its own outside both, pass this
	// check.
	bin := filepath.Join(t.TempDir(), "runsc")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := PreflightRuntime(b, session.RuntimeConfig{RootFS: rootfs, Binary: bin}, workspace, false, false, 0, &policy.Policy{}); err != nil && strings.Contains(err.Error(), "sidecars") {
		t.Fatalf("a runsc with no sidecars refused: %v", err)
	}
	if err := os.Mkdir(filepath.Join(filepath.Dir(bin), "gvisor-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(bin), "gvisor-bin", "gofer"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := PreflightRuntime(b, session.RuntimeConfig{RootFS: rootfs, Binary: bin}, workspace, false, false, 0, &policy.Policy{}); err != nil && strings.Contains(err.Error(), "sidecars") {
		t.Fatalf("sidecars outside both refused: %v", err)
	}
}

// The sessions inside the workspace, through a link as AIRBAG_HOME, are
// refused before a session exists: the copy would copy itself.
func TestSessionsOutsideTheWorkspace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux profile")
	}
	workspace, rootfs := t.TempDir(), t.TempDir()
	bin := filepath.Join(t.TempDir(), "runsc")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(workspace, ".airbag"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(filepath.Join(workspace, ".airbag"), link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AIRBAG_HOME", link)
	b, err := SelectBackend("gvisor", "any")
	if err != nil {
		t.Fatal(err)
	}
	_, err = PreflightRuntime(b, session.RuntimeConfig{RootFS: rootfs, Binary: bin}, workspace, false, false, 0, &policy.Policy{})
	if err == nil || !strings.Contains(err.Error(), "one inside the other") {
		t.Fatalf("sessions inside the workspace passed preflight: %v", err)
	}
}
