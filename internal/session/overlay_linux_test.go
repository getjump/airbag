package session

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A workspace still in an overlay's lower layer is copied up by the
// first write below it, apply's own included: its inode number stays,
// its creation time does not. Recorded once copied up, the root is still
// the session's after that and after the same container restarts, and
// is not in a new container or once made again. The overlay is mounted
// in a user namespace of its own, where there is one.
func TestOverlayCopyUpKeepsRoot(t *testing.T) {
	if os.Getenv("AIRBAG_TEST_OVERLAY") != "" {
		overlayCopyUp(t)
		return
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("no unshare")
	}
	// CI runners and some distributions refuse user namespaces.
	if out, err := exec.CommandContext(t.Context(), unshare, "-rm", "true").CombinedOutput(); err != nil { //nolint:gosec // a probe
		t.Skipf("no user namespace here: %v %s", err, out)
	}
	cmd := exec.CommandContext(t.Context(), unshare, "-rm", os.Args[0], "-test.run=^TestOverlayCopyUpKeepsRoot$", "-test.v") //nolint:gosec // this test binary, in a namespace of its own
	cmd.Env = append(os.Environ(), "AIRBAG_TEST_OVERLAY=1")
	out, err := cmd.CombinedOutput()
	switch {
	case strings.Contains(string(out), "SKIP-OVERLAY"):
		t.Skipf("no overlay in a user namespace here: %s", out)
	case err != nil:
		t.Fatalf("%v: %s", err, out)
	}
}

func overlayCopyUp(t *testing.T) {
	dir := t.TempDir()
	lower, merged := filepath.Join(dir, "l"), filepath.Join(dir, "m")
	for _, d := range []string{filepath.Join(lower, "ws"), merged} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(lower, "ws", "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// mount puts an overlay of lower and the named upper layer at merged:
	// a container, and the same container again after a restart.
	mount := func(upper string) {
		t.Helper()
		work := upper + ".work"
		for _, d := range []string{upper, work} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		opts := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work + ",userxattr"
		if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
			t.Skipf("SKIP-OVERLAY: %v", err)
		}
	}
	unmount := func() {
		t.Helper()
		if err := unix.Unmount(merged, 0); err != nil {
			t.Fatal(err)
		}
	}
	mount(filepath.Join(dir, "u"))
	t.Cleanup(func() { _ = unix.Unmount(merged, 0) }) // before the temporary directory goes
	ws := filepath.Join(merged, "ws")
	id, err := RecordDirID(ws)
	if err != nil {
		t.Fatal(err)
	}
	if id.Born == 0 {
		t.Fatal("no creation time recorded on the overlay")
	}
	if err := os.WriteFile(filepath.Join(ws, "b.txt"), []byte("b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := id.Check(ws); err != nil {
		t.Fatalf("the workspace written below is refused: %v", err)
	}
	unmount()
	mount(filepath.Join(dir, "u"))
	if err := id.Check(ws); err != nil {
		t.Fatalf("the same container after a restart is refused: %v", err)
	}
	unmount()
	mount(filepath.Join(dir, "u2"))
	if err := id.Check(ws); err == nil {
		t.Fatal("a new container from the same image passed")
	}
	if err := os.RemoveAll(ws); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := id.Check(ws); err == nil {
		t.Fatal("a directory made again passed")
	}
}
