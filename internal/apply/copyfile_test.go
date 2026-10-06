package apply

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A FIFO the agent left in its branch is refused at once: a plain open
// would wait for a writer and hold the apply there.
func TestCopyFileRefusesAFIFOWithoutWaiting(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(src, 0o644); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	dst := filepath.Join(dir, "out", "f")
	done := make(chan error, 1)
	go func() { done <- copyFile(src, dst, 0o644) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("copyFile of a FIFO: %v", err)
		}
	case <-time.After(5 * time.Second):
		if w, err := os.OpenFile(src, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = w.Close()
		}
		t.Fatal("copyFile waited on a FIFO")
	}
	if _, err := os.Lstat(dst); !os.IsNotExist(err) {
		t.Fatalf("something was written for the FIFO: %v", err)
	}
}
