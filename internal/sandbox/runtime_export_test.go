package sandbox

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// stream is one side of a result stream: it reads in and keeps what is
// written to it.
type stream struct {
	io.Reader
	out bytes.Buffer
}

func (s *stream) Write(p []byte) (int, error) { return s.out.Write(p) }

func (s *stream) answer() byte {
	if s.out.Len() != 1 {
		return 0xff
	}
	return s.out.Bytes()[0]
}

// guestWorkspace is a tree the agent left: files, and a FIFO.
func guestWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"a.txt", "sub/b.txt"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mkfifo(filepath.Join(root, "sub", "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// sent is what the guest writes for export when the host takes it.
func sent(t *testing.T, export func(io.Writer) (exportStats, error)) ([]byte, error) {
	t.Helper()
	g := &stream{Reader: bytes.NewReader([]byte{exportAck})}
	err := sendExport(g, 7, export)
	return g.out.Bytes(), err
}

func guestSkipping(root string) func(io.Writer) (exportStats, error) {
	return func(w io.Writer) (exportStats, error) { return exportWorkspace(root, w, true) }
}

func TestExportStreamComplete(t *testing.T) {
	root := guestWorkspace(t)
	// Live, both sides at once: the guest waits for the host's answer.
	g, h := net.Pipe()
	errc := make(chan error, 1)
	go func() { errc <- sendExport(g, 7, guestSkipping(root)) }()
	stage := t.TempDir()
	r := receiveExport(h, stage)
	if err := <-errc; err != nil || r.err != nil {
		t.Fatalf("guest: %v, host: %v", err, r.err)
	}
	if r.code != 7 || r.skippedCount != 1 || !slices.Equal(r.skipped, []string{"sub/pipe"}) {
		t.Fatalf("result %+v", r)
	}
	for _, f := range []string{"a.txt", "sub/b.txt"} {
		if b, err := os.ReadFile(filepath.Join(stage, f)); err != nil || string(b) != f {
			t.Fatalf("%s: %q %v", f, b, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(stage, "sub", "pipe")); !os.IsNotExist(err) {
		t.Fatalf("the FIFO was exported: %v", err)
	}
}

// A stream cut anywhere, or changed on the way, is not a complete export,
// and the host tells the guest so.
func TestExportStreamTruncatedOrChanged(t *testing.T) {
	full, err := sent(t, guestSkipping(guestWorkspace(t)))
	if err != nil {
		t.Fatal(err)
	}
	if r := receiveExport(&stream{Reader: bytes.NewReader(full)}, t.TempDir()); r.err != nil {
		t.Fatalf("the whole stream: %v", r.err)
	}
	cuts := []int{0, 1, 5, len(full) / 2, len(full) - 200, len(full) - 1}
	for _, n := range cuts {
		h := &stream{Reader: bytes.NewReader(full[:n])}
		if r := receiveExport(h, t.TempDir()); r.err == nil || h.answer() == exportAck {
			t.Fatalf("a stream cut at %d of %d bytes was taken", n, len(full))
		}
	}
	// One byte of a's contents changed: the tar still reads, the digest
	// does not match.
	i := bytes.Index(full, []byte("sub/b.txt"))
	j := bytes.LastIndex(full, []byte("a.txt"))
	for _, at := range []int{i, j} {
		changed := slices.Clone(full)
		changed[at] ^= 0x20
		h := &stream{Reader: bytes.NewReader(changed)}
		if r := receiveExport(h, t.TempDir()); r.err == nil || h.answer() == exportAck {
			t.Fatalf("a stream changed at %d was taken", at)
		}
	}
}

// A guest whose export fails mid-way (here at a FIFO it may not skip)
// says so; the partial tar is not taken, whatever it holds.
func TestExportGuestFailure(t *testing.T) {
	root := guestWorkspace(t)
	full, err := sent(t, func(w io.Writer) (exportStats, error) { return exportWorkspace(root, w, false) })
	if err == nil || !strings.Contains(err.Error(), "pipe") {
		t.Fatalf("the guest's export did not fail: %v", err)
	}
	h := &stream{Reader: bytes.NewReader(full)}
	r := receiveExport(h, t.TempDir())
	if r.err == nil || !strings.Contains(r.err.Error(), "failed") || h.answer() == exportAck {
		t.Fatalf("a failed export was taken: %v", r.err)
	}
}

// The host's own copy of the real workspace does not skip: a FIFO left
// out there would show as deleted in review.
func TestHostCopyRefusesSpecialFiles(t *testing.T) {
	if _, err := exportWorkspace(guestWorkspace(t), io.Discard, false); err == nil {
		t.Fatal("the host copy skipped a FIFO")
	}
}
