//go:build linux

package sandbox

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/session"
)

// A truncated stream and a guest-reported failure both keep the prior
// branch and fail the run; a complete export replaces it.
func TestExportPublishesOnlyComplete(t *testing.T) {
	t.Setenv("AIRBAG_HOME", filepath.Join(t.TempDir(), "s"))
	root := guestWorkspace(t)
	whole, err := sent(t, guestSkipping(root))
	if err != nil {
		t.Fatal(err)
	}
	failed, _ := sent(t, func(w io.Writer) (exportStats, error) { return exportWorkspace(root, w, false) })
	for name, c := range map[string]struct {
		stream []byte
		ok     bool
	}{
		"truncated": {whole[:len(whole)/2], false},
		"failed":    {failed, false},
		"complete":  {whole, true},
	} {
		t.Run(name, func(t *testing.T) {
			s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: t.TempDir(), Clone: true, Backend: "microvm"})
			if err != nil {
				t.Fatal(err)
			}
			prior := filepath.Join(s.CloneDir(), "prior.txt")
			if err := os.MkdirAll(s.CloneDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(prior, []byte("the branch before this run\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(exportStage(s), 0o700); err != nil {
				t.Fatal(err)
			}
			r := receiveExport(&stream{Reader: bytes.NewReader(c.stream)}, exportStage(s))
			code, err := publishExport(s, r)
			_, priorErr := os.Stat(prior)
			_, newErr := os.Stat(filepath.Join(s.CloneDir(), "a.txt"))
			switch {
			case c.ok && (err != nil || code != 7 || priorErr == nil || newErr != nil):
				t.Fatalf("complete export not published: code=%d err=%v prior=%v new=%v", code, err, priorErr, newErr)
			case !c.ok && (err == nil || code == 0 || priorErr != nil || newErr == nil):
				t.Fatalf("%s export replaced the branch: code=%d err=%v prior=%v new=%v", name, code, err, priorErr, newErr)
			}
			if _, err := os.Stat(exportStage(s)); !os.IsNotExist(err) {
				t.Fatalf("the stage is left: %v", err)
			}
		})
	}
}

// A provider that fails with an export half sent leaves nothing behind:
// abandon stops the importer, though the connection is still open, and
// removes the stage. With no connection at all it returns as well.
func TestAbandonedExportLeavesNoStage(t *testing.T) {
	whole, err := sent(t, guestSkipping(guestWorkspace(t)))
	if err != nil {
		t.Fatal(err)
	}
	listen := func() net.Listener {
		l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", filepath.Join(t.TempDir(), "s"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		return l
	}
	abandoned := func(im *importer) {
		t.Helper()
		done := make(chan struct{})
		go func() { im.abandon(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("abandon waits for an export that will not come")
		}
		if _, err := os.Lstat(im.stage); !os.IsNotExist(err) {
			t.Fatalf("the stage is left: %v", err)
		}
	}

	l := listen()
	stage := filepath.Join(t.TempDir(), "export")
	im := startImport(l, stage)
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(whole[:len(whole)/2]); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; {
		if _, err := os.Lstat(stage); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the import never began")
		}
		time.Sleep(10 * time.Millisecond)
	}
	abandoned(im)

	abandoned(startImport(listen(), filepath.Join(t.TempDir(), "export")))
}

// A whole export through startImport's connection is the importer's
// result, as runMicroVM publishes it.
func TestImportTakesAWholeExport(t *testing.T) {
	whole, err := sent(t, guestSkipping(guestWorkspace(t)))
	if err != nil {
		t.Fatal(err)
	}
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", filepath.Join(t.TempDir(), "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	stage := filepath.Join(t.TempDir(), "export")
	im := startImport(l, stage)
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(whole); err != nil {
		t.Fatal(err)
	}
	var r exportResult
	select {
	case r = <-im.result:
	case <-time.After(10 * time.Second):
		t.Fatal("no result for a whole export")
	}
	if r.err != nil || r.code != 7 {
		t.Fatalf("result %+v", r)
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != exportAck {
		t.Fatalf("the guest is not told the export was taken: %v %x", err, ack)
	}
	if b, err := os.ReadFile(filepath.Join(stage, "a.txt")); err != nil || string(b) != "a.txt" {
		t.Fatalf("a.txt: %q %v", b, err)
	}
}

// A guest whose setup failed sends a failed export, whatever is at the
// workspace's path (an empty placeholder when the disk is not mounted):
// the host keeps the branch. Once set up, the workspace is exported.
func TestGuestExportsOnlyAfterSetup(t *testing.T) {
	t.Setenv("AIRBAG_HOME", filepath.Join(t.TempDir(), "s"))
	placeholder := t.TempDir()
	failed, err := sent(t, exportOf(placeholder, errors.New("mount /dev/vdb: no such device"), nil))
	if err == nil {
		t.Fatal("the guest reports no failure")
	}
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: t.TempDir(), Backend: "microvm", Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.CloneDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.CloneDir(), "kept.txt"), []byte("branch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &stream{Reader: bytes.NewReader(failed)}
	r := receiveExport(h, exportStage(s))
	if r.err == nil || h.answer() == exportAck {
		t.Fatalf("the host took a failed setup's export: %+v", r)
	}
	if _, err := publishExport(s, r); err == nil {
		t.Fatal("a failed setup's export is published")
	}
	if b, err := os.ReadFile(filepath.Join(s.CloneDir(), "kept.txt")); err != nil || string(b) != "branch\n" {
		t.Fatalf("the branch is not kept: %q %v", b, err)
	}
	if _, err := sent(t, exportOf(guestWorkspace(t), nil, nil)); err != nil {
		t.Fatalf("a set-up guest's export: %v", err)
	}
}
