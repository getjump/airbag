package shim

import (
	"os"
	"path/filepath"
	"testing"
)

// Files named as words or --option=value are hashed; secret files are
// not opened (a read by airbag would not taint the session).
func TestPins(t *testing.T) {
	d := t.TempDir()
	for _, f := range []string{"notes.md", "body.txt", ".env"} {
		if err := os.WriteFile(filepath.Join(d, f), []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := pins(d, []string{"release", "notes.md", "--body=body.txt", "--title", "x", ".env", "missing.md"})
	if len(got) != 2 || got[filepath.Join(d, "notes.md")] == "" || got[filepath.Join(d, "body.txt")] == "" {
		t.Fatalf("pins: %v", got)
	}
}
