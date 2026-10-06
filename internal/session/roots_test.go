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

// The workspace and a branched $HOME must be recorded, or the session
// is refused. A $HOME that is not branched is recorded only where a run
// writes in it (macOS, Clone), and only where it can be: one that is
// not there is no reason to refuse. On Linux nothing writes in it, so
// it is neither recorded nor checked.
func TestCreateRecordsTheRootsARunWrites(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := Create(Meta{Workspace: missing, Home: t.TempDir()}); err == nil {
		t.Fatal("a session began in a workspace that is not there")
	}
	if _, err := Create(Meta{Workspace: t.TempDir(), Home: missing, OverHome: true}); err == nil {
		t.Fatal("a session branched a $HOME that is not there")
	}
	// Nor one that cannot be recorded for another reason.
	loop := filepath.Join(t.TempDir(), "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	for _, home := range []string{missing, loop} {
		for _, clone := range []bool{false, true} {
			s, err := Create(Meta{Workspace: t.TempDir(), Home: home, Clone: clone})
			if err != nil || s.HomeID.Real != "" || !s.HomeUnrecorded() {
				t.Fatalf("an unbranched $HOME that cannot be recorded (%s, clone %t): %+v %v", home, clone, s, err)
			}
		}
	}
	for _, clone := range []bool{false, true} {
		ws, home := t.TempDir(), filepath.Join(t.TempDir(), "home")
		if err := os.Mkdir(home, 0o755); err != nil {
			t.Fatal(err)
		}
		s, err := Create(Meta{Workspace: ws, Home: home, Clone: clone})
		if err != nil || s.WorkspaceID.Real == "" || (s.HomeID.Real != "") != clone {
			t.Fatalf("without a $HOME branch (clone %t): %+v %v", clone, s, err)
		}
		s.Status = StatusStopped
		if err := s.Save(); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(home, home+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(home, 0o755); err != nil {
			t.Fatal(err)
		}
		_, err = Resume(s.ID, ws)
		switch {
		case clone && (err == nil || !strings.Contains(err.Error(), "another directory")):
			t.Fatalf("resumed with the $HOME it writes agent state in another directory: %v", err)
		case !clone && err != nil:
			t.Fatalf("a $HOME nothing writes in refused resume: %v", err)
		}
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
	if id.FS == 0 {
		t.Skip("this filesystem gives no ID")
	}
	// The same filesystem mounted again has a new device number: the
	// creation time and the filesystem ID still tell it is the same
	// directory.
	remounted := id
	remounted.Dev++
	if err := remounted.Check(dir); err != nil {
		t.Fatalf("a remount with the creation time unchanged was refused: %v", err)
	}
	// A btrfs snapshot keeps the inode and the creation time, and has a
	// device and a filesystem ID of its own.
	snapshot := remounted
	snapshot.FS++
	if err := snapshot.Check(dir); err == nil || !strings.Contains(err.Error(), "another filesystem") {
		t.Fatalf("a snapshot passed: %v", err)
	}
	// Where the filesystem gives no ID, a new device is refused.
	noID := remounted
	noID.FS = 0
	if err := noID.Check(dir); err == nil || !strings.Contains(err.Error(), "another filesystem") {
		t.Fatalf("a new device without a filesystem ID passed: %v", err)
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

// A recorded filesystem ID must match even on the same device: a device
// formatted again keeps its number, and its root its inode.
func TestCheckComparesFilesystemIDOnSameDevice(t *testing.T) {
	dir := t.TempDir()
	id, err := DirIDOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id.FS == 0 {
		t.Skip("this filesystem gives no ID")
	}
	id.Born = 0
	id.FS++
	if err := id.Check(dir); err == nil || !strings.Contains(err.Error(), "another filesystem") {
		t.Fatalf("another filesystem on the same device passed: %v", err)
	}
}

// A directory removed and made again can get the old inode back, as
// ext4 gives it at once. Without a creation time to tell, its inode
// generation does.
func TestCheckComparesGeneration(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ws")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	id, err := DirIDOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id.Gen == 0 {
		t.Skip("this filesystem gives no inode generation")
	}
	id.Born = 0
	if err := id.Check(dir); err != nil {
		t.Fatalf("the same directory: %v", err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := id.Check(dir); err == nil || !strings.Contains(err.Error(), "another directory") {
		t.Fatalf("a directory made again passed: %v", err)
	}
	other := id
	other.Gen++
	if err := other.Check(dir); err == nil || !strings.Contains(err.Error(), "another directory") {
		t.Fatalf("another generation passed: %v", err)
	}
}
