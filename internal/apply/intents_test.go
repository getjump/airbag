package apply

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/session"
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
