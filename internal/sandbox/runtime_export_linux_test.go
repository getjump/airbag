//go:build linux

package sandbox

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

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
