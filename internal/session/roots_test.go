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
	s, err := Create(Meta{Workspace: ws, Home: t.TempDir(), OverHome: true})
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

// A made-up workspace that does not exist records nothing, and a $HOME
// that is not branched (--no-home, macOS) is not recorded: nothing is
// applied there.
func TestCreateSkipsMissingRoot(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	s, err := Create(Meta{Workspace: "/nonexistent/airbag-ws", Home: t.TempDir(), OverHome: true})
	if err != nil {
		t.Fatal(err)
	}
	if s.WorkspaceID.Real != "" || s.HomeID.Real == "" {
		t.Fatalf("%+v %+v", s.WorkspaceID, s.HomeID)
	}
	s, err = Create(Meta{Workspace: t.TempDir(), Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if s.WorkspaceID.Real == "" || s.HomeID.Real != "" {
		t.Fatalf("without a $HOME branch: %+v %+v", s.WorkspaceID, s.HomeID)
	}
}

// A directory with the inode of a removed one is told apart by its
// creation time, where the filesystem records one.
func TestCheckComparesBirthTime(t *testing.T) {
	dir := t.TempDir()
	id, err := DirIDOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Check(dir); err != nil {
		t.Fatalf("the same directory: %v", err)
	}
	if id.Born == 0 {
		t.Skip("this filesystem records no creation time")
	}
	other := id
	other.Born++
	if err := other.Check(dir); err == nil || !strings.Contains(err.Error(), "another directory") {
		t.Fatalf("a directory born at another time passed: %v", err)
	}
	// The same filesystem mounted again has a new device number: the
	// creation time still tells it is the same directory.
	remounted := id
	remounted.Dev++
	if err := remounted.Check(dir); err != nil {
		t.Fatalf("a remount with the creation time unchanged was refused: %v", err)
	}
}

// Without a creation time to tell, a device that changed is refused:
// another filesystem mounted at the path can have a root of the same
// inode.
func TestCheckComparesDeviceWithoutBirthTime(t *testing.T) {
	dir := t.TempDir()
	id, err := DirIDOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	id.Born = 0
	if err := id.Check(dir); err != nil {
		t.Fatalf("the same directory: %v", err)
	}
	id.Dev++
	if err := id.Check(dir); err == nil || !strings.Contains(err.Error(), "another filesystem") {
		t.Fatalf("another device passed: %v", err)
	}
}
