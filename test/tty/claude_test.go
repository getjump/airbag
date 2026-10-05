//go:build e2e

package tty

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestClaudeInteractive drives the real Claude Code TUI through airbag:
// it waits for the prompt, types a task, approves the permission dialog
// for the Bash call test/mockapi sends, waits for the answer, checks the
// redraw after a resize, and quits with Ctrl-C twice.
func TestClaudeInteractive(t *testing.T) {
	needs(t, "claude")
	f := newFixture(t)
	f.seedClaude()
	addr, mock := f.mock(`[{"name":"Bash","input":{"command":"echo from-claude > claude.txt","description":"write"}}]`)
	// The permission mode and the model are pinned: the defaults differ
	// between accounts and versions, and so would the screens. The
	// model is the mock's; without the last switch Claude Code prints a
	// notice about a model it does not know. The classic renderer keeps
	// the transcript on the main screen.
	agent := "exec env ANTHROPIC_BASE_URL=http://" + addr + " ANTHROPIC_API_KEY=sk-ant-mock" +
		" DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1" +
		" CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1 CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN=1" +
		" CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT=1" +
		" claude --permission-mode default --model mock-model"
	tm := Start(t, 120, 36, f.env(), f.ws, f.run("sh", "-c", mock+agent)...)

	tm.WaitFor(`\? for shortcuts`, 60*time.Second)
	tm.Snap("01-ready")

	tm.TypeSlow("do the task")
	tm.WaitFor(`do the task`, 10*time.Second)
	tm.Send("\r")
	screen := tm.WaitFor(`Do you want to proceed\?`, 30*time.Second)
	tm.Snap("02-permission")
	if !strings.Contains(screen, "echo from-claude > claude.txt") {
		t.Errorf("the dialog does not show the command:\n%s", screen)
	}

	tm.Send("\r") // the first choice, Yes
	tm.WaitFor(`(?s)Bash\(echo from-claude > claude\.txt\).*● done`, 30*time.Second)
	tm.Snap("03-done")

	// Wider, not narrower: an emulator cuts long lines when it shrinks,
	// so only a redraw can make a rule that spans the new width.
	tm.Resize(150, 40)
	tm.WaitFor(`^─{150}$`, 15*time.Second)
	tm.Snap("04-resized")

	tm.Send("\x03")
	tm.WaitForTransient(`(?i)ctrl-c again to exit`, 10*time.Second)
	tm.Snap("05-ctrl-c")
	tm.Send("\x03")
	code := tm.Wait(30 * time.Second)
	if f.airbag != "" {
		tm.WaitFor(`airbag: session s-[0-9a-f]+ ended \(exit 0\)`, 5*time.Second)
	}
	tm.Snap("06-exit")
	if code != 0 {
		t.Errorf("exit status %d, want 0", code)
	}
	f.checkWrote("claude.txt")
}

// seedClaude skips Claude Code's first run (theme, API key and folder
// trust dialogs) in the session's $HOME. The ~/.claude.json keys are
// not documented; they are what 2.1.289 writes once the dialogs are
// answered, so a new version may need others.
func (f *fixture) seedClaude() {
	f.t.Helper()
	state := map[string]any{
		"hasCompletedOnboarding": true,
		"customApiKeyResponses":  map[string]any{"approved": []string{"sk-ant-mock"}, "rejected": []string{}},
		"projects":               map[string]any{f.ws: map[string]any{"hasTrustDialogAccepted": true}},
	}
	// Tips, the turn's duration and animations change between runs.
	settings := map[string]any{
		"theme": "dark", "spinnerTipsEnabled": false, "prefersReducedMotion": true, "showTurnDuration": false,
	}
	for path, v := range map[string]any{".claude.json": state, ".claude/settings.json": settings} {
		b, err := json.Marshal(v)
		if err != nil {
			f.t.Fatalf("%s: %v", path, err)
		}
		f.write(path, string(b))
	}
}
