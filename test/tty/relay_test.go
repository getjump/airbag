//go:build e2e

package tty

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRelay runs the probe as the agent and checks that airbag's relay
// passes the terminal through: the size, a resize, the replies to the
// probe's queries, bracketed paste, focus and mouse input byte for
// byte, and Ctrl-C, which must reach the probe as SIGINT from its own
// terminal and leave airbag to report the probe's exit status.
func TestRelay(t *testing.T) {
	f := newFixture(t)
	probe := f.build("./test/tty/probe")
	tm := Start(t, 120, 36, f.env(), f.ws, f.run(probe)...)

	screen := tm.WaitFor(`^probe ready$`, 60*time.Second)
	tm.Snap("01-ready")
	if !strings.Contains(screen, "probe size 120x36") {
		t.Errorf("the probe started at another size:\n%s", screen)
	}
	// Each query crossed the relay out, the emulator answered, and the
	// answer crossed it back: the probe must have read exactly that.
	replies := tm.Replies()
	for _, name := range []string{"da1", "cpr", "osc11"} {
		m := regexp.MustCompile(`(?m)^probe ` + name + ` (.*)$`).FindStringSubmatch(screen)
		if m == nil {
			t.Errorf("no %s line:\n%s", name, screen)
			continue
		}
		got, err := strconv.Unquote(m[1])
		if err != nil || got == "" || !strings.Contains(replies, got) {
			t.Errorf("probe's %s reply %s is not what the terminal sent, %q", name, m[1], replies)
		}
	}

	for _, in := range []struct{ name, bytes string }{
		{"bracketed paste", "\x1b[200~hello airbag\x1b[201~"},
		{"focus in", "\x1b[I"},
		{"SGR mouse click", "\x1b[<0;10;5M\x1b[<0;10;5m"},
	} {
		tm.Send(in.bytes)
		tm.WaitFor(`^probe in `+regexp.QuoteMeta(strconv.Quote(in.bytes))+`$`, 10*time.Second)
	}
	tm.Resize(100, 30)
	tm.WaitFor(`^probe winch 100x30$`, 10*time.Second)
	tm.Snap("02-input")

	tm.Send("\x03")
	code := tm.Wait(30 * time.Second)
	tm.WaitFor(`^probe sigint$`, 5*time.Second)
	if f.airbag != "" {
		// airbag itself ended normally, after the agent: Ctrl-C did not
		// stop it, and it passes the probe's status on.
		tm.WaitFor(`airbag: session s-[0-9a-f]+ ended \(exit 3\)`, 5*time.Second)
	}
	tm.Snap("03-exit")
	if code != 3 {
		t.Errorf("exit status %d, want the probe's 3", code)
	}
}
