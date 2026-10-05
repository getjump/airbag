package sandbox

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// FuzzReceiveExport feeds the host any result stream a guest could send.
// The guest is told the export was taken exactly when the host takes it,
// the host takes only a stream that, read here on its own, is complete
// and matches its frame, and nothing is written outside the stage.
func FuzzReceiveExport(f *testing.F) {
	g := &stream{Reader: bytes.NewReader([]byte{exportAck})}
	if err := sendExport(g, 7, guestSkipping(fuzzWorkspace(f))); err != nil {
		f.Fatal(err)
	}
	full := g.out.Bytes()
	f.Add(full)
	for _, n := range []int{0, 1, 5, len(full) / 2, len(full) - 1} {
		f.Add(full[:n])
	}
	f.Add(append(bytes.Clone(full), 0))
	f.Fuzz(func(t *testing.T, in []byte) {
		parent := t.TempDir()
		stage := filepath.Join(parent, "stage")
		if err := os.Mkdir(stage, 0o700); err != nil {
			t.Fatal(err)
		}
		h := &stream{Reader: bytes.NewReader(in)}
		r := receiveExport(h, stage)
		if h.out.Len() != 1 || (h.answer() == exportAck) != (r.err == nil) {
			t.Fatalf("answer %v for error %v", h.out.Bytes(), r.err)
		}
		if names, _ := os.ReadDir(parent); len(names) != 1 {
			t.Fatalf("written outside the stage: %v", names)
		}
		if r.err != nil {
			return
		}
		code, payload, frame, ok := readStream(in)
		if !ok || r.code != int(code) || frame.Status != exportComplete {
			t.Fatalf("took a stream that is not complete: %+v", r)
		}
		sum := sha256.Sum256(payload)
		if frame.SHA256 != hex.EncodeToString(sum[:]) || frame.Entries != tarEntries(payload) {
			t.Fatalf("took a stream its frame does not match: %+v", frame)
		}
	})
}

// fuzzWorkspace is a small tree a guest could export.
func fuzzWorkspace(f *testing.F) string {
	root := f.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		f.Fatal(err)
	}
	for _, p := range []string{"a.txt", "sub/b.txt"} {
		if err := os.WriteFile(filepath.Join(root, p), []byte(p), 0o644); err != nil {
			f.Fatal(err)
		}
	}
	if err := os.Symlink("a.txt", filepath.Join(root, "link")); err != nil {
		f.Fatal(err)
	}
	return root
}

// readStream splits a result stream as the format says: the exit code,
// the chunks up to the empty one, and the completion frame. The host
// reads no further, so what follows the frame does not count.
func readStream(b []byte) (code byte, payload []byte, frame exportFrame, ok bool) {
	next := func() ([]byte, bool) {
		if len(b) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(b)
		if int64(len(b)-4) < int64(n) {
			return nil, false
		}
		c := b[4 : 4+n]
		b = b[4+n:]
		return c, true
	}
	if len(b) < 1 {
		return 0, nil, frame, false
	}
	code, b = b[0], b[1:]
	for {
		c, ok := next()
		if !ok {
			return 0, nil, frame, false
		}
		if len(c) == 0 {
			break
		}
		payload = append(payload, c...)
	}
	c, ok := next()
	if !ok || json.Unmarshal(c, &frame) != nil {
		return 0, nil, frame, false
	}
	return code, payload, frame, true
}

// tarEntries counts the headers of a tar that ends properly, or -1.
func tarEntries(b []byte) int {
	tr := tar.NewReader(bytes.NewReader(b))
	for n := 0; ; n++ {
		if _, err := tr.Next(); err == io.EOF {
			return n
		} else if err != nil {
			return -1
		}
	}
}
