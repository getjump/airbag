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
// its creation time does not. The root must still be the session's.
// The overlay is mounted in a user namespace of its own, where there is
// one.
func TestOverlayCopyUpKeepsRoot(t *testing.T) {
	if os.Getenv("AIRBAG_TEST_OVERLAY") != "" {
		overlayCopyUp(t)
		return
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("no unshare")
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
	lower, upper, work, merged := filepath.Join(dir, "l"), filepath.Join(dir, "u"), filepath.Join(dir, "w"), filepath.Join(dir, "m")
	for _, d := range []string{filepath.Join(lower, "ws"), upper, work, merged} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(lower, "ws", "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work + ",userxattr"
	if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		t.Skipf("SKIP-OVERLAY: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(merged, 0) }) // before the temporary directory goes
	ws := filepath.Join(merged, "ws")
	id, err := DirIDOf(ws)
	if err != nil {
		t.Fatal(err)
	}
	var before unix.Statx_t
	_ = unix.Statx(unix.AT_FDCWD, ws, 0, unix.STATX_BTIME, &before)
	if err := os.WriteFile(filepath.Join(ws, "b.txt"), []byte("b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var after unix.Statx_t
	_ = unix.Statx(unix.AT_FDCWD, ws, 0, unix.STATX_BTIME, &after)
	t.Logf("creation time before copy-up %d.%09d, after %d.%09d", before.Btime.Sec, before.Btime.Nsec, after.Btime.Sec, after.Btime.Nsec)
	if err := id.Check(ws); err != nil {
		t.Fatalf("the workspace copied up is refused: %v", err)
	}
}
