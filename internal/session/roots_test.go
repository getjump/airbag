package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Create records where the workspace and $HOME lead, and a stopped
// session does not resume once its workspace is another directory.
func TestCreateRecordsRootsAndResumeChecksThem(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.Mkdir(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := Create(Meta{Workspace: ws, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if s.WorkspaceID.Real == "" || s.HomeID.Real == "" || s.WorkspaceID.Ino == 0 {
		t.Fatalf("roots not recorded: %+v %+v", s.WorkspaceID, s.HomeID)
	}
	s.Status = StatusStopped
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(ws, ws+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Resume(s.ID, ws); err == nil || !strings.Contains(err.Error(), "another directory") {
		t.Fatalf("resumed on another directory: %v", err)
	}
	if err := os.Remove(ws); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(ws+".old", ws); err != nil {
		t.Fatal(err)
	}
	if _, err := Resume(s.ID, ws); err != nil {
		t.Fatalf("the workspace moved back does not resume: %v", err)
	}
}

// A made-up workspace that does not exist records nothing.
func TestCreateSkipsMissingRoot(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	s, err := Create(Meta{Workspace: "/nonexistent/airbag-ws", Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if s.WorkspaceID.Real != "" || s.HomeID.Real == "" {
		t.Fatalf("%+v %+v", s.WorkspaceID, s.HomeID)
	}
}
