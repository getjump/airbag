package sandbox

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRejectGuestArchiveEscapes(t *testing.T) {
	cases := []struct {
		name    string
		headers []*tar.Header
	}{
		{"traversal", []*tar.Header{{Name: "../outside", Typeflag: tar.TypeReg}}},
		{"absolute", []*tar.Header{{Name: "/outside", Typeflag: tar.TypeReg}}},
		{"symlink-parent", []*tar.Header{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: ".."}, {Name: "link/outside", Typeflag: tar.TypeReg}}},
		{"hardlink", []*tar.Header{{Name: "link", Typeflag: tar.TypeLink, Linkname: "/outside"}}},
		{"device", []*tar.Header{{Name: "dev", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3}}},
		{"duplicate", []*tar.Header{{Name: "file", Typeflag: tar.TypeReg}, {Name: "file", Typeflag: tar.TypeReg}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tar.NewWriter(&buf)
			for _, h := range tc.headers {
				if err := w.WriteHeader(h); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := importWorkspace(t.TempDir(), &buf); err == nil {
				t.Fatal("accepted hostile export")
			}
		})
	}
}

func TestWorkspaceArchivePreservesFilesAndDoesNotFollowLinks(t *testing.T) {
	source, dst := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "script"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/host-only-canary", filepath.Join(source, "link")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := exportWorkspace(source, &buf, false); err != nil {
		t.Fatal(err)
	}
	if _, err := importWorkspace(dst, &buf); err != nil {
		t.Fatal(err)
	}
	link, err := os.Readlink(filepath.Join(dst, "link"))
	if err != nil || link != "/host-only-canary" {
		t.Fatalf("link=%q err=%v", link, err)
	}
	st, err := os.Stat(filepath.Join(dst, "script"))
	if err != nil || st.Mode().Perm()&0o111 == 0 {
		t.Fatalf("lost executable mode: %v", err)
	}
}

func TestGuestExportSizeLimit(t *testing.T) {
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	if err := w.WriteHeader(&tar.Header{Name: "huge", Typeflag: tar.TypeReg, Size: archiveLimit + 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := importWorkspace(t.TempDir(), &buf); err == nil {
		t.Fatal("accepted oversized guest file")
	}
}

func TestSymlinkedWorkspaceExportsItsFiles(t *testing.T) {
	dir := t.TempDir()
	real, link, dst := filepath.Join(dir, "real"), filepath.Join(dir, "link"), t.TempDir()
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"keep.txt", "sub/nested.txt"} {
		if err := os.WriteFile(filepath.Join(real, f), []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("real", link); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := exportWorkspace(link, &buf, false); err != nil {
		t.Fatal(err)
	}
	if _, err := importWorkspace(dst, &buf); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"keep.txt", "sub/nested.txt"} {
		if b, err := os.ReadFile(filepath.Join(dst, f)); err != nil || string(b) != f {
			t.Fatalf("%s through a symlinked workspace: %q %v", f, b, err)
		}
	}
}

// Modes survive the copy whatever the umask: review compares them, and a
// group-writable file must not show as changed.
func TestArchiveKeepsModesPastUmask(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	source, dst := t.TempDir(), t.TempDir()
	for name, mode := range map[string]os.FileMode{"group-writable": 0o664, "private": 0o600, "script": 0o775} {
		p := filepath.Join(source, name)
		if err := os.WriteFile(p, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if _, err := exportWorkspace(source, &buf, false); err != nil {
		t.Fatal(err)
	}
	if _, err := importWorkspace(dst, &buf); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{"group-writable": 0o664, "private": 0o600, "script": 0o775} {
		st, err := os.Stat(filepath.Join(dst, name))
		if err != nil || st.Mode().Perm() != mode {
			t.Fatalf("%s: %v, want %v (%v)", name, st.Mode().Perm(), mode, err)
		}
	}
}

// A file the walk found regular and something else has made a FIFO since
// fails at once instead of blocking the copy.
func TestOpenRegularDoesNotWaitOnAFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "f"), 0o600); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "r"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	done := make(chan error, 1)
	go func() {
		f, err := openRegular(root, "f")
		if err == nil {
			_ = f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO opened as a regular file")
		}
	case <-time.After(5 * time.Second):
		if w, err := os.OpenFile(filepath.Join(dir, "f"), os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = w.Close()
		}
		t.Fatal("the open waited on a FIFO")
	}
	f, err := openRegular(root, "r")
	if err != nil {
		t.Fatalf("a regular file: %v", err)
	}
	_ = f.Close()
}
