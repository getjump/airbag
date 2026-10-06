package apply

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/outbox"
)

// The agent may make any path of its branch a link once an apply took its
// version out, during a run resumed after a partial apply, say. Giving that
// version back must write it into the branch or nowhere: through a link to
// a host directory it would put a file the user never reviewed there.
func TestRollbackWritesNothingThroughALinkInTheBranch(t *testing.T) {
	for _, clone := range []bool{false, true} {
		t.Run(map[bool]string{false: "upper", true: "clone"}[clone], func(t *testing.T) {
			t.Setenv("AIRBAG_HOME", t.TempDir())
			ws := filepath.Join(t.TempDir(), "ws")
			if err := os.MkdirAll(filepath.Join(ws, "a"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(ws, "a", "b.txt"), []byte("user\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Clone: clone})
			if err != nil {
				t.Fatal(err)
			}
			s.Status = session.StatusStopped
			branch := s.WSBranch()
			if clone {
				// A clone holds the whole workspace.
				if err := os.MkdirAll(filepath.Join(branch, "a"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for rel, body := range map[string]string{"a/b.txt": "agent\n", "other.txt": "kept in the session\n"} {
				p := filepath.Join(branch, rel)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			box, err := outbox.Open(s.EffectsPath())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = box.Close() }()
			var out bytes.Buffer
			if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Only: []string{"a"}, Out: &out}); err != nil {
				t.Fatal(err, out.String())
			}
			if got := read(t, filepath.Join(ws, "a", "b.txt")); got != "agent\n" {
				t.Fatalf("not applied: %q", got)
			}
			outside := t.TempDir()
			if err := os.RemoveAll(filepath.Join(branch, "a")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(branch, "a")); err != nil {
				t.Fatal(err)
			}
			out.Reset()
			err = Rollback(s, nil, &out)
			if left, _ := os.ReadDir(outside); len(left) != 0 {
				t.Fatalf("rollback wrote %v through the branch's link, outside the session", left)
			}
			if err == nil {
				t.Fatalf("rollback through a link in the branch reported success: %s", out.String())
			}
			// The user's version from before the apply is still kept.
			if !strings.Contains(err.Error(), "return the agent's version") {
				t.Fatalf("rollback: %v", err)
			}
			held, herr := HeldVersions(s)
			if herr != nil || len(held) != 1 {
				t.Fatalf("held versions %v %v", held, herr)
			}
			if got := read(t, held[0].Saved); got != "user\n" {
				t.Fatalf("the kept version is %q", got)
			}
			// With the link gone, the rollback finishes.
			if err := os.Remove(filepath.Join(branch, "a")); err != nil {
				t.Fatal(err)
			}
			out.Reset()
			if err := Rollback(s, nil, &out); err != nil {
				t.Fatalf("the rollback once the link is gone: %v\n%s", err, out.String())
			}
			if got := read(t, filepath.Join(ws, "a", "b.txt")); got != "user\n" {
				t.Fatalf("not rolled back: %q", got)
			}
			if got := read(t, filepath.Join(branch, "a", "b.txt")); got != "agent\n" {
				t.Fatalf("the agent's version is not back in the session: %q", got)
			}
		})
	}
}

// On macOS the agent may write the clone's own entry in the session. A
// link put there must not lead the rollback elsewhere: os.OpenRoot
// follows links in the name it opens.
func TestRollbackRefusesABranchThatIsALink(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(filepath.Join(ws, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "a", "b.txt"), []byte("user\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	clone := s.CloneDir()
	for rel, body := range map[string]string{"a/b.txt": "agent\n", "other.txt": "kept in the session\n"} {
		p := filepath.Join(clone, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Only: []string{"a"}, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	// The apply took a/b.txt out of the clone; the clone itself moves
	// away, and a link to an outside directory takes its place.
	outside := t.TempDir()
	if err := os.Rename(clone, clone+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, clone); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	err = Rollback(s, nil, &out)
	if left, _ := os.ReadDir(outside); len(left) != 0 {
		t.Fatalf("rollback wrote %v through the link at the clone's place", left)
	}
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("rollback through a branch that is a link: %v\n%s", err, out.String())
	}
}

// What the agent left at a replaced directory's path that is not a
// directory gets no opaque mark and holds nothing up: a FIFO opened to
// mark it would block the rollback until someone wrote to it.
func TestMarkOpaqueLeavesWhatIsNotADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	done := make(chan error, 2)
	go func() {
		done <- markOpaqueIn(r, "fifo")
		done <- markOpaqueIn(r, "file")
	}()
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("marking a FIFO blocked")
		}
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	if err := markOpaqueIn(r, "out/x"); err == nil {
		t.Fatal("a path that leads out of the branch was not refused")
	}
}

// A version the agent put at the path after giveBack found it empty (in
// a run still going) stays: the agent's version from the journal is not
// renamed over it, and no temp file is left beside it.
func TestGiveBackKeepsWhatAppearedSince(t *testing.T) {
	branch, src := t.TempDir(), filepath.Join(t.TempDir(), "journal-version")
	if err := os.WriteFile(src, []byte("from the journal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(branch, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(branch, "d", "f"), []byte("newer, the agent's\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", filepath.Join(branch, "d", "l")); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(branch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := copyFileIn(r, src, "d/f", 0o644); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(branch, "d", "f")); got != "newer, the agent's\n" {
		t.Fatalf("the agent's newer version was replaced: %q", got)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink("from the journal", link); err != nil {
		t.Fatal(err)
	}
	if err := copyTreeIn(r, link, "d/l"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.Readlink(filepath.Join(branch, "d", "l")); got != "elsewhere" {
		t.Fatalf("the agent's link was replaced: %q", got)
	}
	if ents, _ := os.ReadDir(filepath.Join(branch, "d")); len(ents) != 2 {
		t.Fatalf("left beside them: %v", ents)
	}
}

// A rollback of deletions only writes nothing in a clone, and stops at a
// clone that is a link all the same, keeping your versions in the session.
func TestRollbackOfADeletionRefusesABranchThatIsALink(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(filepath.Join(ws, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	for rel, body := range map[string]string{"a/b.txt": "user\n", "other.txt": "user\n"} {
		if err := os.WriteFile(filepath.Join(ws, rel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	// The agent deleted a/b.txt in its clone and changed other.txt.
	clone := s.CloneDir()
	if err := os.MkdirAll(filepath.Join(clone, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clone, "other.txt"), []byte("agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Only: []string{"a/b.txt"}, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if _, err := os.Lstat(filepath.Join(ws, "a", "b.txt")); !os.IsNotExist(err) {
		t.Fatalf("the deletion was not applied: %v", err)
	}
	outside := t.TempDir()
	if err := os.Rename(clone, clone+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, clone); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Rollback(s, nil, &out); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("rollback of a deletion through a branch that is a link: %v\n%s", err, out.String())
	}
	if held, err := HeldVersions(s); err != nil || len(held) == 0 {
		t.Fatalf("the stopped rollback kept nothing in the session: %v, %v", held, err)
	}
}

// A live run holds the rollback off: its agent could change the branch
// under it, and the two would save the session over each other. A
// running mark a killed run left, with nothing answering on its control
// socket, does not: rollback is the way back to the user's versions.
func TestRollbackWaitsOnlyForALiveRun(t *testing.T) {
	// A short root: a unix socket path has room for about 100 bytes.
	root, err := os.MkdirTemp("/tmp", "rb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	t.Setenv("AIRBAG_HOME", root)
	ws := t.TempDir()
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.WSUpper(), "f"), []byte("agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	s.Status = session.StatusRunning
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", s.ControlSock())
	if err != nil {
		t.Fatal(err)
	}
	if err := Rollback(s, nil, &out); err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatalf("rolled back under a live run: %v", err)
	}
	if got := read(t, filepath.Join(ws, "f")); got != "agent\n" {
		t.Fatalf("the refused rollback changed the file: %q", got)
	}
	// The run is gone; its socket file is left, as after a SIGKILL.
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = l.Close()
	out.Reset()
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatalf("a running mark a killed run left held the rollback up: %v\n%s", err, out.String())
	}
	if _, err := os.Lstat(filepath.Join(ws, "f")); !os.IsNotExist(err) {
		t.Fatalf("not rolled back: %v", err)
	}
	// The dead running mark goes with the rollback: kept, it would hold
	// run --session, apply and discard off.
	if saved, err := session.Load(s.Dir); err != nil || saved.Status != session.StatusStopped {
		t.Fatalf("the session after the rollback: %v, %v", saved, err)
	}
}

// A run holds the session's run lock from before it marks the session
// running, so a rollback started before its host services answer waits
// for it too.
func TestRollbackWaitsForTheRunLock(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := t.TempDir()
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.WSUpper(), "f"), []byte("agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	run, err := session.Load(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := run.LockRun()
	if err != nil {
		t.Fatal(err)
	}
	if err := Rollback(s, nil, &out); err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatalf("rolled back while a run held the lock: %v", err)
	}
	unlock()
	out.Reset()
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatalf("the rollback once the run let go: %v\n%s", err, out.String())
	}
	// The rollback let go of the lock when it ended.
	again, err := run.LockRun()
	if err != nil {
		t.Fatalf("the rollback kept the run lock: %v", err)
	}
	again()
}

// On macOS the agent holds the agent lock it was passed, and nothing ends
// it with airbag: after airbag is killed, a rollback waits for the agent
// (or a process of its that keeps the descriptor), not only for airbag.
func TestRollbackWaitsForAnAgentThatOutlivesItsRun(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := t.TempDir()
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.WSUpper(), "f"), []byte("agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	// A resumed run takes the run lock and passes the agent lock to its
	// agent; then airbag is killed, which lets go of the run lock.
	run, err := session.Load(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := run.LockRun()
	if err != nil {
		t.Fatal(err)
	}
	lock, err := run.LockAgent()
	if err != nil {
		t.Fatal(err)
	}
	agent := exec.CommandContext(t.Context(), "sleep", "30")
	agent.ExtraFiles = []*os.File{lock}
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	_ = lock.Close()
	unlock()
	if err := Rollback(s, nil, &out); err == nil || !strings.Contains(err.Error(), "outlive airbag") {
		t.Fatalf("rolled back beside the agent: %v", err)
	}
	if got := read(t, filepath.Join(ws, "f")); got != "agent\n" {
		t.Fatalf("the refused rollback changed the file: %q", got)
	}
	_ = agent.Process.Kill()
	_ = agent.Wait()
	out.Reset()
	if err := Rollback(s, nil, &out); err != nil {
		t.Fatalf("the rollback once the agent is gone: %v\n%s", err, out.String())
	}
}
