package sandbox

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
)

// The microVM's result stream on vsock port 4002, guest to host:
//
//	exit code   1 byte
//	tar         chunks: a 4-byte big-endian length and that many bytes,
//	            ended by a chunk of length 0
//	completion  a 4-byte length and an exportFrame as JSON
//
// then host to guest one byte, exportAck once the host has checked the
// frame against what it read, anything else when it has not; the guest
// reboots after that answer. The end of a tar is not proof the export
// finished: a stream that stops early, a frame that does not say
// complete, or an entry count or digest other than the host's keeps the
// prior branch and fails the run. None of this is attestation: a
// compromised guest can send any tree, and review and apply still decide.
const (
	maxExportChunk = 1 << 20
	maxExportFrame = 64 << 10
	maxListed      = 32 // skipped files named in the frame; the rest counted
	exportAck      = 1
	exportComplete = "complete"
)

type exportFrame struct {
	Status       string   `json:"status"`
	Entries      int      `json:"entries"`
	SHA256       string   `json:"sha256"`
	Skipped      []string `json:"skipped,omitempty"`
	SkippedCount int      `json:"skipped_count,omitempty"`
}

// exportResult is what the host made of a result stream.
type exportResult struct {
	code         int
	skipped      []string // as the guest named them: untrusted, print quoted
	skippedCount int
	err          error
}

var errAfterArchive = errors.New("data after the end of the archive")

// chunkWriter frames what is written to it as chunks and hashes it.
type chunkWriter struct {
	w   io.Writer
	sum hash.Hash
	buf []byte
}

func newChunkWriter(w io.Writer) *chunkWriter {
	return &chunkWriter{w: w, sum: sha256.New(), buf: make([]byte, 0, maxExportChunk)}
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		k := min(len(p), maxExportChunk-len(c.buf))
		c.buf = append(c.buf, p[:k]...)
		p = p[k:]
		if len(c.buf) == maxExportChunk {
			if err := c.flush(); err != nil {
				return n - len(p), err
			}
		}
	}
	return n, nil
}

func (c *chunkWriter) flush() error {
	if len(c.buf) == 0 {
		return nil
	}
	c.sum.Write(c.buf)
	err := writeFrame(c.w, c.buf)
	c.buf = c.buf[:0]
	return err
}

// end flushes the last chunk and writes the empty one that ends the tar.
func (c *chunkWriter) end() error {
	if err := c.flush(); err != nil {
		return err
	}
	return writeFrame(c.w, nil)
}

func writeFrame(w io.Writer, b []byte) error {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b))) //nolint:gosec // at most maxExportChunk or maxExportFrame
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readLength(r io.Reader, limit int) (int, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return 0, err
	}
	if v := binary.BigEndian.Uint32(n[:]); v <= uint32(limit) { //nolint:gosec // limit is a small positive constant
		return int(v), nil
	}
	return 0, fmt.Errorf("a frame longer than %d bytes", limit)
}

// sendExport is the guest's side: the exit code, export's tar, the
// completion frame, then the host's answer. It returns export's error,
// or an error when the host did not take the export.
func sendExport(conn io.ReadWriter, code int, export func(io.Writer) (exportStats, error)) error {
	if _, err := conn.Write([]byte{byte(code)}); err != nil { //nolint:gosec // exit codes fit a byte
		return err
	}
	cw := newChunkWriter(conn)
	st, xerr := export(cw)
	if err := cw.end(); err != nil {
		return errors.Join(xerr, err)
	}
	f := exportFrame{Status: exportComplete, Entries: st.entries, SHA256: hex.EncodeToString(cw.sum.Sum(nil)),
		Skipped: st.skipped[:min(len(st.skipped), maxListed)], SkippedCount: len(st.skipped)}
	if xerr != nil {
		f.Status = "failed: " + xerr.Error()
	}
	b, err := json.Marshal(f)
	if err == nil && len(b) > maxExportFrame {
		f.Skipped, f.Status = nil, f.Status[:min(len(f.Status), 1024)]
		b, err = json.Marshal(f)
	}
	if err != nil {
		return errors.Join(xerr, err)
	}
	if err := writeFrame(conn, b); err != nil {
		return errors.Join(xerr, err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		return errors.Join(xerr, fmt.Errorf("no answer from the host: %w", err))
	}
	if ack[0] != exportAck {
		return errors.Join(xerr, errors.New("the host did not take the export"))
	}
	return xerr
}

// receiveExport is the host's side: it unpacks the tar into stage and
// answers the guest. The result's error is nil only for a complete
// export whose entries and digest match what was read.
func receiveExport(conn io.ReadWriter, stage string) (r exportResult) {
	r.code = 1
	defer func() {
		answer := byte(0)
		if r.err == nil {
			answer = exportAck
		}
		_, _ = conn.Write([]byte{answer})
	}()
	var code [1]byte
	if _, err := io.ReadFull(conn, code[:]); err != nil {
		r.err = fmt.Errorf("no exit code: %w", err)
		return r
	}
	type imported struct {
		n   int
		err error
	}
	pr, pw := io.Pipe()
	done := make(chan imported, 1)
	go func() {
		n, err := importWorkspace(stage, pr)
		stop := err
		if stop == nil {
			stop = errAfterArchive // what comes after the tar's end is refused
		}
		_ = pr.CloseWithError(stop)
		done <- imported{n, err}
	}()
	sum := sha256.New()
	into := io.MultiWriter(pw, sum)
	var serr error
	for {
		n, err := readLength(conn, maxExportChunk)
		if err != nil {
			serr = fmt.Errorf("the stream ended inside the archive: %w", err)
			break
		}
		if n == 0 {
			break
		}
		if _, err := io.CopyN(into, conn, int64(n)); err != nil {
			serr = fmt.Errorf("the archive: %w", err)
			break
		}
	}
	if serr != nil {
		_ = pw.CloseWithError(serr)
		<-done
		r.err = serr
		return r
	}
	_ = pw.Close()
	got := <-done
	var f exportFrame
	n, err := readLength(conn, maxExportFrame)
	if err == nil {
		b := make([]byte, n)
		if _, err = io.ReadFull(conn, b); err == nil {
			err = json.Unmarshal(b, &f)
		}
	}
	r.skipped, r.skippedCount = f.Skipped, f.SkippedCount
	switch {
	case err != nil:
		r.err = fmt.Errorf("no completion frame: %w", err)
	case f.Status != exportComplete:
		r.err = fmt.Errorf("the guest reports the export %q", f.Status)
	case got.err != nil:
		r.err = fmt.Errorf("the archive: %w", got.err)
	case f.Entries != got.n:
		r.err = fmt.Errorf("the guest sent %d entries, the host read %d", f.Entries, got.n)
	case f.SHA256 != hex.EncodeToString(sum.Sum(nil)):
		r.err = errors.New("the archive's digest differs from the guest's")
	default:
		r.code = int(code[0])
	}
	return r
}
