package apply

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/outbox"
)

func testBox(t *testing.T) (*session.Session, *outbox.Box) {
	t.Helper()
	ws := t.TempDir()
	box, err := outbox.Open(filepath.Join(t.TempDir(), "effects.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = box.Close() })
	return &session.Session{Meta: session.Meta{ID: "s-test", Workspace: ws}}, box
}

func status(t *testing.T, box *outbox.Box, id string) string {
	t.Helper()
	all, err := box.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range all {
		if it.ID == id {
			return it.Status
		}
	}
	t.Fatalf("no intent %s", id)
	return ""
}

// An intent recorded as running when airbag stopped is reported as
// unknown and never run again.
func TestRunningBecomesUnknown(t *testing.T) {
	s, box := testBox(t)
	it, err := box.Push(outbox.Intent{Kind: "git.push", Argv: []string{"git", "push", "origin", "main"}, Cwd: s.Workspace})
	if err != nil {
		t.Fatal(err)
	}
	it.Status = outbox.Running
	if err := box.Update(it); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runIntents(s, box, false, nil, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if got := status(t, box, it.ID); got != outbox.Unknown {
		t.Fatalf("status %s, want unknown; output: %s", got, out.String())
	}
	out.Reset()
	if err := runIntents(s, box, false, nil, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if got := status(t, box, it.ID); got != outbox.Unknown || out.Len() != 0 {
		t.Fatalf("second run touched it: %s %q", got, out.String())
	}
}

// One that was running when airbag stopped becomes unknown even with the
// workspace moved, so its outcome can still be recorded; the rest wait.
func TestRunningBecomesUnknownWithRootMoved(t *testing.T) {
	s, box := testBox(t)
	id, err := session.DirIDOf(s.Workspace)
	if err != nil {
		t.Fatal(err)
	}
	s.WorkspaceID = id
	it, _ := box.Push(outbox.Intent{Kind: outbox.KindPush, Argv: []string{"git", "push", "origin", "main"}, Cwd: s.Workspace})
	it.Status = outbox.Running
	if err := box.Update(it); err != nil {
		t.Fatal(err)
	}
	later, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool"}, Cwd: s.Workspace})
	moveRoot(t, s.Workspace)
	var out bytes.Buffer
	if err := runIntents(s, box, false, nil, Options{Out: &out}); err == nil || !strings.Contains(err.Error(), "leads to") {
		t.Fatalf("the outbox ran in a moved workspace: %v", err)
	}
	if got := status(t, box, it.ID); got != outbox.Unknown {
		t.Fatalf("status %s, want unknown: %q", got, out.String())
	}
	if err := box.Resolve(it.ID, true); err != nil {
		t.Fatalf("its outcome cannot be recorded: %v", err)
	}
	if got := status(t, box, later.ID); got != outbox.Pending {
		t.Fatalf("the later intent is %s", got)
	}
}

// After a session put git config or hooks into the repository, its
// pushes wait for --trust-git, with or without --yes.
func TestRiskyWaitsForTrust(t *testing.T) {
	s, box := testBox(t)
	it, err := box.Push(outbox.Intent{Kind: "git.push", Argv: []string{"git", "push", "origin", "main"}, Cwd: s.Workspace})
	if err != nil {
		t.Fatal(err)
	}
	for _, yes := range []bool{true, false} {
		var out bytes.Buffer
		if err := runIntents(s, box, true, nil, Options{Yes: yes, Out: &out}); err != nil {
			t.Fatal(err)
		}
		if got := status(t, box, it.ID); got != outbox.Pending || !strings.Contains(out.String(), "--trust-git") {
			t.Fatalf("yes=%v: status %s, output %q", yes, got, out.String())
		}
	}
}

// tool puts a program on PATH that records its arguments, and returns
// where it writes them.
func tool(t *testing.T, name, exit string) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "ran")
	script := "#!/bin/sh\necho \"$0 $*\" >> " + log + "\necho done-output\nexit " + exit + "\n"
	if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	return log
}

func ran(log string) string {
	b, _ := os.ReadFile(log)
	return string(b)
}

func sum(t *testing.T, p string) string {
	t.Helper()
	s, err := hashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A deferred command runs on the host only when the user says so, one
// by one: --yes leaves it pending.
func TestCmdConfirmedOneByOne(t *testing.T) {
	s, box := testBox(t)
	log := tool(t, "pubtool", "0")
	_ = os.WriteFile(filepath.Join(s.Workspace, "notes.md"), []byte("v1 notes\n"), 0o644)
	it, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool", "release", "--notes", "notes.md"}, Cwd: s.Workspace,
		Files: map[string]string{"notes.md": sum(t, filepath.Join(s.Workspace, "notes.md"))}})
	var out bytes.Buffer
	if err := runIntents(s, box, false, nil, Options{Yes: true, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if status(t, box, it.ID) != outbox.Pending || ran(log) != "" || !strings.Contains(out.String(), "without --yes") {
		t.Fatalf("--yes ran it: %q, %q", ran(log), out.String())
	}
	out.Reset()
	if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("y\n")), Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if status(t, box, it.ID) != outbox.Done || !strings.Contains(ran(log), "pubtool release --notes notes.md") {
		t.Fatalf("not run: %s %q %q", status(t, box, it.ID), ran(log), out.String())
	}
}

// A file the command names that changed since it was queued stops it.
func TestCmdPinnedFile(t *testing.T) {
	s, box := testBox(t)
	log := tool(t, "pubtool", "0")
	p := filepath.Join(s.Workspace, "notes.md")
	_ = os.WriteFile(p, []byte("reviewed\n"), 0o644)
	it, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool", "notes.md"}, Cwd: s.Workspace,
		Files: map[string]string{"notes.md": sum(t, p)}})
	_ = os.WriteFile(p, []byte("changed\n"), 0o644)
	var out bytes.Buffer
	if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("y\n")), Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if status(t, box, it.ID) != outbox.Rejected || ran(log) != "" {
		t.Fatalf("ran on changed content: %q %q", ran(log), out.String())
	}
}

// The program comes from outside the workspace.
func TestCmdProgramInWorkspace(t *testing.T) {
	s, box := testBox(t)
	_ = os.WriteFile(filepath.Join(s.Workspace, "pubtool"), []byte("#!/bin/sh\ntouch "+filepath.Join(s.Workspace, "pwned")+"\n"), 0o755)
	t.Setenv("PATH", s.Workspace+":"+os.Getenv("PATH"))
	it, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool"}, Cwd: s.Workspace})
	var out bytes.Buffer
	if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("y\n")), Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if status(t, box, it.ID) != outbox.Rejected {
		t.Fatalf("status %s: %q", status(t, box, it.ID), out.String())
	}
	if _, err := os.Stat(filepath.Join(s.Workspace, "pwned")); err == nil {
		t.Fatal("a program from the workspace ran")
	}
}

// The same through a workspace whose path has a link in it (~/code ->
// /mnt/data/code; /tmp -> /private/tmp on macOS): the program's resolved
// path is still inside the workspace.
func TestCmdProgramInLinkedWorkspace(t *testing.T) {
	s, box := testBox(t)
	link := filepath.Join(t.TempDir(), "code")
	if err := os.Symlink(s.Workspace, link); err != nil {
		t.Fatal(err)
	}
	s.Workspace = link
	_ = os.WriteFile(filepath.Join(link, "pubtool"), []byte("#!/bin/sh\ntouch "+filepath.Join(link, "pwned")+"\n"), 0o755)
	t.Setenv("PATH", link+":"+os.Getenv("PATH"))
	it, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool"}, Cwd: link})
	var out bytes.Buffer
	if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("y\n")), Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if status(t, box, it.ID) != outbox.Rejected {
		t.Fatalf("status %s: %q", status(t, box, it.ID), out.String())
	}
	if _, err := os.Stat(filepath.Join(link, "pwned")); err == nil {
		t.Fatal("a program from the workspace ran")
	}
}

// After a failure the intents behind it wait; the next apply runs them.
func TestFailureStopsTheRest(t *testing.T) {
	s, box := testBox(t)
	log := tool(t, "failing", "1")
	tool(t, "pubtool", "0")
	one, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"failing"}, Cwd: s.Workspace})
	two, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool", "after"}, Cwd: s.Workspace})
	var out bytes.Buffer
	if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("y\ny\n")), Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if status(t, box, one.ID) != outbox.Failed || status(t, box, two.ID) != outbox.Pending || !strings.Contains(ran(log), "failing") {
		t.Fatalf("%s %s: %q", status(t, box, one.ID), status(t, box, two.ID), out.String())
	}
}

// With apply --branch the working tree is not the result, so commands
// wait; a session that changed git config waits for --trust-git.
func TestCmdWaits(t *testing.T) {
	s, box := testBox(t)
	log := tool(t, "pubtool", "0")
	it, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool"}, Cwd: s.Workspace})
	s.Branch = "agent-work"
	var out bytes.Buffer
	in := bufio.NewReader(strings.NewReader("y\ny\n"))
	if err := runIntents(s, box, false, in, Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	s.Branch = ""
	if err := runIntents(s, box, true, in, Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if status(t, box, it.ID) != outbox.Pending || ran(log) != "" ||
		!strings.Contains(out.String(), "branch agent-work") || !strings.Contains(out.String(), "--trust-git") {
		t.Fatalf("ran: %q %q", ran(log), out.String())
	}
}

// On macOS the agent worked in the clone; its intents run in the real
// workspace.
func TestHostDir(t *testing.T) {
	s := &session.Session{Meta: session.Meta{Workspace: "/w", Clone: true}, Dir: "/sessions/s-1"}
	if got := hostDir(s, filepath.Join(s.CloneDir(), "sub")); got != "/w/sub" {
		t.Fatalf("got %s", got)
	}
	if got := hostDir(s, "/w/sub"); got != "/w/sub" {
		t.Fatalf("got %s", got)
	}
}

// A program reached through a symlink into the workspace is refused.
func TestCmdProgramLinkedIntoWorkspace(t *testing.T) {
	s, box := testBox(t)
	_ = os.WriteFile(filepath.Join(s.Workspace, "tool"), []byte("#!/bin/sh\ntouch "+filepath.Join(s.Workspace, "pwned")+"\n"), 0o755)
	bin := t.TempDir()
	if err := os.Symlink(filepath.Join(s.Workspace, "tool"), filepath.Join(bin, "pubtool")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	it, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool"}, Cwd: s.Workspace})
	var out bytes.Buffer
	if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("y\n")), Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Workspace, "pwned")); err == nil || status(t, box, it.ID) != outbox.Rejected {
		t.Fatalf("ran a program from the workspace: %q", out.String())
	}
}

// After an outcome that is not known, the intents queued later wait
// until the user records what happened; then they run.
func TestUnknownHoldsLaterIntentsUntilResolved(t *testing.T) {
	s, box := testBox(t)
	log := tool(t, "pubtool", "0")
	push, _ := box.Push(outbox.Intent{Kind: outbox.KindPush, Argv: []string{"git", "push", "origin", "main"}, Cwd: s.Workspace})
	push.Status, push.Output = outbox.Unknown, "airbag stopped while this ran"
	if err := box.Update(push); err != nil {
		t.Fatal(err)
	}
	cmd, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool"}, Cwd: s.Workspace})
	var out bytes.Buffer
	if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("y\n")), Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if ran(log) != "" || !strings.Contains(out.String(), "airbag outbox resolve "+push.ID) {
		t.Fatalf("ran after an unknown outcome: %q", out.String())
	}
	if err := box.Resolve(cmd.ID, true); err == nil {
		t.Fatal("recorded an outcome for a pending intent")
	}
	if err := box.Resolve(push.ID, true); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("y\n")), Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if ran(log) == "" || status(t, box, cmd.ID) != outbox.Done || status(t, box, push.ID) != outbox.Done {
		t.Fatalf("did not run after the outcome was recorded: %q", out.String())
	}
}

// A command left pending by --yes holds nothing back.
func TestPendingCmdDoesNotHoldLaterIntents(t *testing.T) {
	s, box := testBox(t)
	log := tool(t, "pubtool", "0")
	first, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool", "one"}, Cwd: s.Workspace})
	second, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool", "two"}, Cwd: s.Workspace})
	var out bytes.Buffer
	if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("n\ny\n")), Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if status(t, box, first.ID) != outbox.Rejected || status(t, box, second.ID) != outbox.Done || !strings.Contains(ran(log), "two") {
		t.Fatalf("first %s, second %s: %q", status(t, box, first.ID), status(t, box, second.ID), out.String())
	}
}

// A deferred command waits while the session's links in the real files
// lead into $HOME outside the workspace, to a secret file or nowhere: an
// argument that is or runs through one reads or writes there without
// showing it, however it is spelled.
func TestCmdWaitsForLinksOut(t *testing.T) {
	for _, c := range []struct {
		name string
		make func(ws, home string) (string, error) // the link; its path is recorded as applied
		runs bool
	}{
		{"to a secret file", func(ws, _ string) (string, error) {
			_ = os.WriteFile(filepath.Join(ws, ".env"), []byte("TOKEN=x\n"), 0o600)
			return filepath.Join(ws, "notes.md"), os.Symlink(".env", filepath.Join(ws, "notes.md"))
		}, false},
		{"to a secret file in another case", func(ws, _ string) (string, error) {
			_ = os.WriteFile(filepath.Join(ws, ".ENV"), []byte("TOKEN=x\n"), 0o600)
			return filepath.Join(ws, "notes.md"), os.Symlink(".ENV", filepath.Join(ws, "notes.md"))
		}, false},
		{"into home", func(ws, home string) (string, error) {
			_ = os.WriteFile(filepath.Join(home, "hosts.yml"), []byte("token\n"), 0o600)
			return filepath.Join(ws, "docs"), os.Symlink(home, filepath.Join(ws, "docs"))
		}, false},
		{"nowhere, into home", func(ws, home string) (string, error) {
			return filepath.Join(ws, "out.txt"), os.Symlink(filepath.Join(home, ".bashrc"), filepath.Join(ws, "out.txt"))
		}, false},
		{"nowhere, where the user cannot create anything", func(ws, _ string) (string, error) {
			// What appears there later, a process's files among them,
			// is not known now.
			return filepath.Join(ws, "notes.md"), os.Symlink("/proc/999999999/environ", filepath.Join(ws, "notes.md"))
		}, false},
		{"in a loop of links", func(ws, _ string) (string, error) {
			_ = os.Symlink("b", filepath.Join(ws, "a"))
			return filepath.Join(ws, "notes.md"), os.Symlink("a/x", filepath.Join(ws, "notes.md"))
		}, false},
		{"from home into home", func(_, home string) (string, error) {
			return filepath.Join(home, "notes.md"), os.Symlink(filepath.Join(home, ".netrc-like"), filepath.Join(home, "notes.md"))
		}, false},
		{"to the user's data outside home", func(ws, _ string) (string, error) {
			// Another disk, or the session's own storage under /var/tmp.
			elsewhere := t.TempDir()
			_ = os.WriteFile(filepath.Join(elsewhere, "data.txt"), []byte("mine\n"), 0o600)
			return filepath.Join(ws, "notes.md"), os.Symlink(filepath.Join(elsewhere, "data.txt"), filepath.Join(ws, "notes.md"))
		}, false},
		{"to a system directory above user data", func(ws, home string) (string, error) {
			return filepath.Join(ws, "all"), os.Symlink(filepath.Dir(home), filepath.Join(ws, "all"))
		}, false},
		{"to a system directory", func(ws, _ string) (string, error) {
			// What lies below a directory is not known, whatever its name.
			return filepath.Join(ws, "share"), os.Symlink("/usr", filepath.Join(ws, "share"))
		}, false},
		{"to a file of the user's that anyone may read", func(ws, _ string) (string, error) {
			// Read-only, in a directory the user cannot write, so only
			// the owner tells it from a system file.
			dir := filepath.Join(t.TempDir(), "ro")
			_ = os.Mkdir(dir, 0o755)
			_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine\n"), 0o444)
			_ = os.Chmod(dir, 0o555)
			t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
			return filepath.Join(ws, "notes.md"), os.Symlink(filepath.Join(dir, "notes.txt"), filepath.Join(ws, "notes.md"))
		}, false},
		{"to a process's own file", func(ws, _ string) (string, error) {
			// The user's own process: not a file of someone else's.
			return filepath.Join(ws, "notes.md"), os.Symlink("/proc/self/status", filepath.Join(ws, "notes.md"))
		}, false},
		{"inside the workspace", func(ws, _ string) (string, error) {
			_ = os.WriteFile(filepath.Join(ws, "body.md"), []byte("ok\n"), 0o644)
			return filepath.Join(ws, "notes.md"), os.Symlink("body.md", filepath.Join(ws, "notes.md"))
		}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if strings.Contains(c.name, "process") {
				if _, err := os.Stat("/proc/self/status"); err != nil {
					t.Skip("no /proc here")
				}
			}
			s, box := testBox(t)
			s.Home = filepath.Dir(s.Workspace) // the workspace is in $HOME
			log := tool(t, "pubtool", "0")
			link, err := c.make(s.Workspace, s.Home)
			if err != nil {
				t.Fatal(err)
			}
			s.Applied = map[string]time.Time{link: time.Now()}
			it, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool", "--body-file", "notes.md"}, Cwd: s.Workspace})
			var out bytes.Buffer
			if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("y\n")), Options{Out: &out}); err != nil {
				t.Fatal(err)
			}
			if got := ran(log) != ""; got != c.runs {
				t.Fatalf("ran = %v, want %v: %q", got, c.runs, out.String())
			}
			if c.runs {
				return
			}
			if status(t, box, it.ID) != outbox.Pending || !strings.Contains(out.String(), link) {
				t.Fatalf("not held, or the link not named: %q", out.String())
			}
			// Once the user removes the link, the command runs.
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("y\n")), Options{Out: &out}); err != nil {
				t.Fatal(err)
			}
			if ran(log) == "" {
				t.Fatalf("held after the link was removed: %q", out.String())
			}
		})
	}
}

// A link to a system file (a venv's interpreter in /usr/bin) holds
// nothing: anyone may read it and the user cannot replace it. Root may
// write anywhere, so for root nothing outside the workspace is public.
func TestCmdLinkToSystemFileRuns(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("as root every place is writable")
	}
	s, box := testBox(t)
	s.Home = filepath.Dir(s.Workspace)
	log := tool(t, "pubtool", "0")
	link := filepath.Join(s.Workspace, "python")
	if err := os.Symlink("/bin/sh", link); err != nil {
		t.Fatal(err)
	}
	s.Applied = map[string]time.Time{link: time.Now()}
	_, _ = box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool"}, Cwd: s.Workspace})
	var out bytes.Buffer
	if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("y\n")), Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if ran(log) == "" {
		t.Fatalf("held by a link to a system file: %q", out.String())
	}
}

// A machine's configuration anyone may read can carry credentials, so a
// link to it holds commands, as one to a directory of root's does.
func TestCmdLinkToSystemConfigWaits(t *testing.T) {
	for _, target := range []string{"/etc/passwd", "/usr/bin"} {
		if _, err := os.Stat(target); err != nil {
			continue
		}
		s, box := testBox(t)
		s.Home = filepath.Dir(s.Workspace)
		log := tool(t, "pubtool", "0")
		link := filepath.Join(s.Workspace, "notes.md")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		s.Applied = map[string]time.Time{link: time.Now()}
		_, _ = box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool"}, Cwd: s.Workspace})
		var out bytes.Buffer
		if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("y\n")), Options{Out: &out}); err != nil {
			t.Fatal(err)
		}
		if ran(log) != "" {
			t.Fatalf("ran with a link to %s: %q", target, out.String())
		}
	}
}

// Through the real apply: a link the agent made in a new directory is
// recorded and holds the session's commands until the user trusts it.
func TestApplyRecordsLinksThatHoldCommands(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	ws := filepath.Join(t.TempDir(), "ws")
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "python"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: t.TempDir(), Clone: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Status = session.StatusStopped
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.CloneDir(), ".venv/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(elsewhere, "python"), filepath.Join(s.CloneDir(), ".venv/bin/python")); err != nil {
		t.Fatal(err)
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	log := tool(t, "pubtool", "0")
	it, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool"}, Cwd: s.CloneDir()})
	var out bytes.Buffer
	if err := Apply(s, mustScan(t, s), box, Options{Yes: true, Force: true, Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if !strings.Contains(out.String(), ".venv/bin/python") || !strings.Contains(out.String(), "--trust-links") {
		t.Fatalf("not held by the applied link: %q", out.String())
	}
	out.Reset()
	if err := Apply(s, nil, box, Options{TrustLinks: true, In: strings.NewReader("y\n"), Out: &out}); err != nil {
		t.Fatal(err, out.String())
	}
	if ran(log) == "" || status(t, box, it.ID) != outbox.Done {
		t.Fatalf("--trust-links did not run it: %q", out.String())
	}
}

// An argument naming the session's own storage is refused, whatever the
// spelling around its ID.
func TestCmdNamesSessionStorage(t *testing.T) {
	s, box := testBox(t)
	log := tool(t, "pubtool", "0")
	it, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool", "--body-file=//var/tmp/airbag-501/S-TEST/./ws/clone/notes.md"}, Cwd: s.Workspace})
	var out bytes.Buffer
	if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("y\n")), Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if ran(log) != "" || status(t, box, it.ID) != outbox.Rejected {
		t.Fatalf("ran on the session's storage: %q", out.String())
	}
}

// Pushes and deferred commands wait while the workspace leads elsewhere
// than when the session began.
func TestOutboxWaitsForMovedRoot(t *testing.T) {
	s, box := testBox(t)
	id, err := session.DirIDOf(s.Workspace)
	if err != nil {
		t.Fatal(err)
	}
	s.WorkspaceID = id
	log := tool(t, "pubtool", "0")
	it, _ := box.Push(outbox.Intent{Kind: outbox.KindCmd, Argv: []string{"pubtool", "release"}, Cwd: s.Workspace})
	if err := os.Rename(s.Workspace, s.Workspace+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), s.Workspace); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runIntents(s, box, false, bufio.NewReader(strings.NewReader("y\n")), Options{Out: &out}); err == nil || !strings.Contains(err.Error(), "leads to") {
		t.Fatalf("the outbox ran in a moved workspace: %v", err)
	}
	if status(t, box, it.ID) != outbox.Pending || ran(log) != "" {
		t.Fatalf("ran: %s %q", status(t, box, it.ID), ran(log))
	}
}

// movesOnRead answers the confirmation, and before it does, moves the
// workspace as the host could while the prompt waits.
type movesOnRead struct {
	t     *testing.T
	ws    string
	moved bool
}

func (m *movesOnRead) Read(p []byte) (int, error) {
	if !m.moved {
		m.moved = true
		moveRoot(m.t, m.ws)
	}
	return copy(p, "y\n"), nil
}

// The workspace is checked again as each intent starts: one moved while
// its confirmation waited takes no push and no command.
func TestOutboxRechecksRootAfterConfirm(t *testing.T) {
	for _, kind := range []string{outbox.KindCmd, outbox.KindPush} {
		t.Run(kind, func(t *testing.T) {
			s, box := testBox(t)
			id, err := session.DirIDOf(s.Workspace)
			if err != nil {
				t.Fatal(err)
			}
			s.WorkspaceID = id
			name, argv := "pubtool", []string{"pubtool", "release"}
			if kind == outbox.KindPush {
				name, argv = "git", []string{"git", "push", "origin", "main"}
			}
			log := tool(t, name, "0")
			it, _ := box.Push(outbox.Intent{Kind: kind, Argv: argv, Cwd: s.Workspace})
			var out bytes.Buffer
			in := &movesOnRead{t: t, ws: s.Workspace}
			if err := runIntents(s, box, false, bufio.NewReader(in), Options{Out: &out}); err == nil || !strings.Contains(err.Error(), "leads to") {
				t.Fatalf("ran in a workspace moved while it was confirmed: %v %q", err, out.String())
			}
			if !in.moved || status(t, box, it.ID) != outbox.Pending || strings.Contains(ran(log), " "+strings.Join(argv[1:], " ")+"\n") {
				t.Fatalf("ran: %v %s %q", in.moved, status(t, box, it.ID), ran(log))
			}
		})
	}
}
