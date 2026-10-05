package review

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A bind mount gives the workspace a second name with no link to
// follow: the target is inside by file, as apply decides.
func TestReportComparesTheWorkspaceThroughABindMount(t *testing.T) {
	ws, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Mkdir(alias, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(ws, alias, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("no bind mount here: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(alias, unix.MNT_DETACH) })
	if w := linkReport(t, ws, "latest", filepath.Join(alias, "v2")); strings.Contains(w, "trust-links") {
		t.Errorf("a link into the workspace through a bind mount holds the command: %s", w)
	}
	if w := linkReport(t, ws, "docs", filepath.Join(filepath.Dir(alias), "elsewhere")); !strings.Contains(w, "1 links") {
		t.Errorf("a link next to the bind mount is not counted: %s", w)
	}
}
