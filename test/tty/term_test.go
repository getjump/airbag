//go:build e2e

package tty

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
	"github.com/creack/pty"
)

// settle is how long the screen must stay unchanged before WaitFor
// trusts a match: TUIs redraw in several writes, and a match on a
// half-drawn frame would race with the rest of it.
const settle = 300 * time.Millisecond

// Term is a program on a pseudo-terminal of the test's own, with a
// terminal emulator on the other end. The emulator answers the
// program's queries (DA, DSR, OSC colours) as a terminal would, and the
// test reads its screen.
type Term struct {
	t     testing.TB
	emu   *vt.SafeEmulator
	pty   *os.File
	cmd   *exec.Cmd
	dir   string // artifacts
	cast  *cast
	done  chan struct{} // closed once the program has exited
	out   chan struct{} // closed once its output is read to the end
	in    chan struct{} // closed once the emulator's replies are copied
	state *os.ProcessState

	mu      sync.Mutex
	replies []byte // what the emulator answered, in order

	svgs sync.WaitGroup // Snap's freeze runs
}

// Start runs argv in dir with exactly env, on a cols x rows terminal.
func Start(t testing.TB, cols, rows int, env []string, dir string, argv ...string) *Term {
	t.Helper()
	// Term ends the program itself: hangup first, as a closed terminal
	// would, which a context's kill cannot do.
	cmd := exec.CommandContext(context.Background(), argv[0], argv[1:]...) //nolint:gosec // the test's own command line
	cmd.Env, cmd.Dir = env, dir
	adir := artifactDir(t)
	c, err := newCast(filepath.Join(adir, "session.cast"), cols, rows, env)
	if err != nil {
		t.Fatal(err)
	}
	// pty.StartWithSize makes the program a session leader with the
	// terminal as its controlling one, as a login shell would have.
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)}) //nolint:gosec // test sizes are small
	if err != nil {
		_ = c.close()
		t.Fatalf("start %v: %v", argv, err)
	}
	tm := &Term{
		t: t, emu: vt.NewSafeEmulator(cols, rows), pty: f, cmd: cmd, dir: adir, cast: c,
		done: make(chan struct{}), out: make(chan struct{}), in: make(chan struct{}),
	}
	t.Logf("started %q; artifacts in %s", argv, adir)
	go func() {
		defer close(tm.out)
		buf := make([]byte, 32<<10)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				tm.cast.output(buf[:n])
				_, _ = tm.emu.Write(buf[:n])
			}
			if err != nil {
				return // EIO once the last process with the terminal is gone
			}
		}
	}()
	// The emulator's replies go back as the terminal's input.
	go func() {
		defer close(tm.in)
		buf := make([]byte, 4096)
		for {
			n, err := tm.emu.Read(buf)
			if n > 0 {
				tm.mu.Lock()
				tm.replies = append(tm.replies, buf[:n]...)
				tm.mu.Unlock()
				_, _ = f.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		_ = cmd.Wait()
		tm.state = cmd.ProcessState
		close(tm.done)
	}()
	t.Cleanup(tm.stop)
	return tm
}

// stop ends what is left of the program. A program still running here
// belongs to a failed test: it gets the hangup a closed terminal sends,
// then SIGKILL. The group is killed either way: in a run without
// airbag, the mock API is a background job in it.
func (tm *Term) stop() {
	pgrp := -tm.cmd.Process.Pid
	select {
	case <-tm.done:
	default:
		_ = syscall.Kill(pgrp, syscall.SIGHUP)
		select {
		case <-tm.done:
		case <-time.After(5 * time.Second):
		}
	}
	_ = syscall.Kill(pgrp, syscall.SIGKILL)
	<-tm.done
	_ = tm.pty.Close()
	<-tm.out
	// SafeEmulator locks neither Read nor Close, and Close sets a flag
	// Read checks; closing the pipe Read reads from ends the copy as
	// well, without the race.
	if c, ok := tm.emu.InputPipe().(io.Closer); ok {
		_ = c.Close()
	}
	<-tm.in
	tm.svgs.Wait()
	if err := tm.cast.close(); err != nil {
		tm.t.Errorf("session.cast: %v", err)
	}
}

// Screen is the plain text on the screen, without trailing blanks.
// It comes from Render, which SafeEmulator locks (String it does not),
// with the styles stripped.
func (tm *Term) Screen() string {
	lines := strings.Split(ansi.Strip(tm.emu.Render()), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

// WaitFor waits until pattern (multi-line mode) matches the screen and
// the screen has not changed for settle, and returns that screen.
func (tm *Term) WaitFor(pattern string, timeout time.Duration) string {
	tm.t.Helper()
	return tm.waitFor(pattern, timeout, settle)
}

// WaitForTransient waits until pattern matches, without the settle: for
// a state too short to wait out, such as Claude Code's "Press Ctrl-C
// again to exit", which lasts about 0.8 s.
func (tm *Term) WaitForTransient(pattern string, timeout time.Duration) string {
	tm.t.Helper()
	return tm.waitFor(pattern, timeout, 0)
}

func (tm *Term) waitFor(pattern string, timeout, stable time.Duration) string {
	tm.t.Helper()
	re := regexp.MustCompile("(?m)" + pattern)
	deadline := time.Now().Add(timeout)
	last, since := tm.Screen(), time.Now()
	for {
		s := tm.Screen()
		if s != last {
			last, since = s, time.Now()
		}
		matched := re.MatchString(s)
		if matched && time.Since(since) >= stable {
			return s
		}
		ended := false
		select {
		case <-tm.out:
			ended = true
		default:
		}
		switch {
		case ended && !matched:
			tm.fail("the program's output ended before %q appeared", pattern)
		case time.Now().After(deadline):
			tm.fail("timed out after %s waiting for %q", timeout, pattern)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fail keeps the screen as failure.txt (and .svg) and stops the test.
func (tm *Term) fail(format string, args ...any) {
	tm.t.Helper()
	tm.Snap("failure")
	tm.t.Fatalf(format+"; screen:\n%s", append(args, tm.Screen())...)
}

// Replies is what the emulator has answered the program's queries with.
func (tm *Term) Replies() string {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return string(tm.replies)
}

// Send writes s to the terminal as typed or pasted input: in one write.
func (tm *Term) Send(s string) {
	tm.t.Helper()
	if _, err := io.WriteString(tm.pty, s); err != nil {
		tm.t.Fatalf("send %q: %v", s, err)
	}
}

// TypeSlow types s one character at a time. Both TUIs take a burst of
// characters for a paste: Claude Code shows it as pasted text, Codex
// holds Enter back for a while after one.
func (tm *Term) TypeSlow(s string) {
	tm.t.Helper()
	for _, r := range s {
		tm.Send(string(r))
		time.Sleep(40 * time.Millisecond)
	}
}

// Resize changes the terminal's size. The kernel sends SIGWINCH to the
// terminal's foreground process group, as for a resized window. The
// emulator changes first, so the program's redraw lands at the new size.
func (tm *Term) Resize(cols, rows int) {
	tm.t.Helper()
	tm.emu.Resize(cols, rows)
	if err := pty.Setsize(tm.pty, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)}); err != nil { //nolint:gosec // test sizes are small
		tm.t.Fatalf("resize to %dx%d: %v", cols, rows, err)
	}
	tm.cast.event("r", fmt.Sprintf("%dx%d", cols, rows))
}

// Snap keeps the screen as name.txt and, when freeze is in PATH, as
// name.svg with the colours. The SVG is drawn in the background, so a
// snap does not delay the test's next key.
func (tm *Term) Snap(name string) {
	tm.t.Helper()
	base := filepath.Join(tm.dir, name)
	styled := tm.emu.Render()
	if err := os.WriteFile(base+".txt", []byte(tm.Screen()+"\n"), 0o644); err != nil {
		tm.t.Errorf("snap %s: %v", name, err)
	}
	freeze, err := exec.LookPath("freeze")
	if err != nil {
		return
	}
	tm.svgs.Add(1)
	go func() {
		defer tm.svgs.Done()
		cmd := exec.CommandContext(context.Background(), freeze, "--language", "ansi", "--output", base+".svg") //nolint:gosec // freeze from PATH, into the test's artifacts
		cmd.Stdin = strings.NewReader(styled)
		if out, err := cmd.CombinedOutput(); err != nil {
			tm.t.Logf("snap %s: freeze: %v: %s", name, err, out)
		}
	}()
}

// Wait waits for the program to exit and returns its exit status: -1
// when a signal killed it.
func (tm *Term) Wait(timeout time.Duration) int {
	tm.t.Helper()
	select {
	case <-tm.done:
	case <-time.After(timeout):
		tm.fail("still running after %s", timeout)
	}
	// Its last output may still be in the terminal; a process left in
	// the background can hold the terminal open, so the wait is short.
	select {
	case <-tm.out:
	case <-time.After(2 * time.Second):
	}
	if ws, ok := tm.state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		tm.t.Logf("%s was killed by %v", tm.cmd.Path, ws.Signal())
	}
	return tm.state.ExitCode()
}

// artifactDir is $TTY_ARTIFACTS/<test name>, or a temporary directory
// that goes away with the test.
func artifactDir(t testing.TB) string {
	root := os.Getenv("TTY_ARTIFACTS")
	if root == "" {
		return t.TempDir()
	}
	dir := filepath.Join(root, strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // under the directory the user named for the artifacts
		t.Fatal(err)
	}
	return dir
}

// cast writes an asciicast v2 recording: a header line, then one
// [seconds, "o", text] line per output chunk and [seconds, "r",
// "COLSxROWS"] per resize. asciinema plays it, agg makes a GIF of it.
type cast struct {
	mu    sync.Mutex
	f     *os.File
	start time.Time
	carry []byte // an incomplete UTF-8 sequence at the end of a chunk
	err   error
}

func newCast(path string, cols, rows int, env []string) (*cast, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	c := &cast{f: f, start: time.Now()}
	header := map[string]any{"version": 2, "width": cols, "height": rows, "timestamp": c.start.Unix()}
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "TERM="); ok {
			header["env"] = map[string]string{"TERM": v}
		}
	}
	c.line(header)
	return c, c.err
}

// output records a chunk. JSON strings hold text, so a UTF-8 sequence
// split across two reads waits for its end, as asciinema does.
func (c *cast) output(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b = append(c.carry, b...)
	cut := len(b)
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				cut = i
			}
			break
		}
	}
	c.carry = append([]byte(nil), b[cut:]...)
	if cut > 0 {
		c.line([]any{c.since(), "o", string(b[:cut])})
	}
}

func (c *cast) event(code, data string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.line([]any{c.since(), code, data})
}

func (c *cast) since() float64 {
	return float64(time.Since(c.start).Microseconds()) / 1e6
}

func (c *cast) line(v any) {
	if c.err != nil {
		return
	}
	b, err := json.Marshal(v)
	if err == nil {
		_, err = c.f.Write(append(b, '\n'))
	}
	c.err = err
}

func (c *cast) close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.f.Close(); err != nil && c.err == nil {
		c.err = err
	}
	return c.err
}
