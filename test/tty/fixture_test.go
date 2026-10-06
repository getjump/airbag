//go:build e2e

// Package tty runs sessions through airbag in a pseudo-terminal and
// checks what reaches the screen and the agent: the relay's bytes,
// sizes and signals, with a probe for an agent (relay_test.go), and the
// interactive Claude Code and Codex TUIs against test/mockapi.
//
//	go test -tags e2e ./test/tty/... -v
//
// The tests run airbag from PATH (or $AIRBAG) as a regular user.
// TTY_ARTIFACTS=dir keeps each test's screens and session.cast in
// dir/<test>. TTY_DIRECT=1 runs the same programs without airbag, to
// check the harness itself where airbag cannot run (as root, or with
// no user namespaces).
package tty

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fixture struct {
	t      *testing.T
	home   string // the session's $HOME: a new directory in the real one
	ws     string // the workspace, a git repository in home
	bin    string // what the test builds
	airbag string // empty under TTY_DIRECT
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the end-to-end tests are Linux-only")
	}
	f := &fixture{t: t}
	if os.Getenv("TTY_DIRECT") == "" {
		if os.Geteuid() == 0 {
			t.Skip("airbag run needs a regular user, not root; TTY_DIRECT=1 runs the harness without airbag")
		}
		p, err := exec.LookPath(cmp.Or(os.Getenv("AIRBAG"), "airbag"))
		if err != nil {
			t.Fatalf("%v: install airbag or set AIRBAG; TTY_DIRECT=1 runs without it", err)
		}
		f.airbag = p
	}
	// The sandbox has a /tmp of its own, so everything the session uses
	// lives in $HOME, as in test/*-e2e.sh. A $HOME of its own also
	// keeps the agents' first-run state out of the user's.
	realHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	f.home, err = os.MkdirTemp(realHome, ".airbag-tty-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(f.home); err != nil {
			t.Logf("remove %s: %v", f.home, err)
		}
	})
	f.ws, f.bin = filepath.Join(f.home, "proj"), filepath.Join(f.home, ".bin")
	for _, d := range []string{f.ws, f.bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.git("init", "-q", "-b", "main")
	if f.airbag != "" {
		t.Cleanup(func() {
			// airbag keeps a session's branch until it is applied or
			// discarded.
			if out, err := f.command(f.airbag, "discard", "--yes").CombinedOutput(); err != nil {
				t.Logf("airbag discard: %v: %s", err, out)
			}
		})
	}
	return f
}

// env is the whole environment of a session. Nothing comes from the
// test's own but PATH and who the user is: a proxy, a locale or an
// agent's marker from the outside would change what the TUIs draw.
func (f *fixture) env() []string {
	env := []string{
		"HOME=" + f.home,
		"PATH=" + os.Getenv("PATH"),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"LANG=C.UTF-8",
		"TZ=UTC",
	}
	for _, k := range []string{"USER", "LOGNAME", "AIRBAG_HOME"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// run is the command line that runs argv as the session's agent.
func (f *fixture) run(argv ...string) []string {
	if f.airbag == "" {
		return argv
	}
	return append([]string{f.airbag, "run", "--"}, argv...)
}

// command is name with the session's environment, in the workspace.
func (f *fixture) command(name string, args ...string) *exec.Cmd {
	// Not the test's context: discard runs in a cleanup, after it ends.
	cmd := exec.CommandContext(context.Background(), name, args...) //nolint:gosec // git and airbag, with the test's own arguments
	cmd.Dir, cmd.Env = f.ws, f.env()
	return cmd
}

func (f *fixture) git(args ...string) {
	f.t.Helper()
	if out, err := f.command("git", args...).CombinedOutput(); err != nil {
		f.t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

// build compiles a command of this repository into f.bin. It is static,
// so it runs the same in the sandbox.
func (f *fixture) build(pkg string) string {
	f.t.Helper()
	out := filepath.Join(f.bin, filepath.Base(pkg))
	cmd := exec.CommandContext(f.t.Context(), "go", "build", "-o", out, pkg) //nolint:gosec // a package of this repository, into the test's directory
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		f.t.Fatalf("go build %s: %v: %s", pkg, err, b)
	}
	return out
}

// write puts content at path, relative to the session's $HOME.
func (f *fixture) write(path, content string) {
	f.t.Helper()
	p := filepath.Join(f.home, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// mock returns the address of a test/mockapi that answers with calls
// (a JSON list of tool calls, see its doc), and the shell command that
// starts it in the background. The mock runs next to the agent, so in
// the sandbox: the sandbox's network has a loopback of its own.
func (f *fixture) mock(calls string) (addr, start string) {
	f.t.Helper()
	bin := f.build("./test/mockapi")
	f.write("calls.json", calls)
	// A free port of the host's, for runs without airbag.
	l, err := (&net.ListenConfig{}).Listen(f.t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	addr = l.Addr().String()
	_ = l.Close()
	// Its output would hold the terminal open after the agent exits.
	start = fmt.Sprintf("%s -addr %s -script %s >/dev/null 2>&1 & sleep 0.5; ",
		quote(bin), addr, quote(filepath.Join(f.home, "calls.json")))
	return addr, start
}

// checkWrote checks that the agent's tool call wrote name: into the
// session's branch under airbag, so review lists it and the workspace
// does not have it; into the workspace itself without airbag.
func (f *fixture) checkWrote(name string) {
	f.t.Helper()
	_, err := os.Stat(filepath.Join(f.ws, name))
	switch {
	case f.airbag == "":
		if err != nil {
			f.t.Errorf("the tool call did not write %s: %v", name, err)
		}
	case err == nil:
		f.t.Errorf("%s reached the real workspace", name)
	default:
		out, err := f.command(f.airbag, "review", "--json").CombinedOutput()
		if err != nil {
			f.t.Errorf("airbag review failed: %v\n%s", err, out)
			return
		}
		var report struct {
			Changes []struct{ Path, Kind, Layer string }
		}
		if err := json.Unmarshal(out, &report); err != nil {
			f.t.Errorf("decode airbag review: %v\n%s", err, out)
			return
		}
		for _, change := range report.Changes {
			if change.Path == name && change.Kind == "added" && change.Layer == "ws" {
				return
			}
		}
		f.t.Errorf("airbag review changes = %v, want added workspace file %q", report.Changes, name)
	}
}

// needs skips the test when name is not in PATH.
func needs(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not in PATH", name)
	}
}

// quote makes s one word for sh.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
