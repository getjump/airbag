//go:build e2e

package tty

import (
	"fmt"
	"testing"
	"time"
)

// TestCodexInteractive drives the real Codex TUI through airbag: it
// waits for the composer, types a task, waits for the exec_command call
// test/mockapi sends and the answer after it, and quits with Ctrl-C.
func TestCodexInteractive(t *testing.T) {
	needs(t, "codex")
	f := newFixture(t)
	addr, mock := f.mock(`[{"name":"exec_command","input":{"cmd":"echo from-codex > codex.txt"}}]`)
	// A trusted project and no animations, so the first screen is the
	// composer and it settles. The header shows the model once Codex
	// has read this config.
	f.write(".codex/config.toml", fmt.Sprintf(`model = "mock-model"
model_provider = "mock"
check_for_update_on_startup = false

[model_providers.mock]
name = "mock"
base_url = "http://%s/v1"
wire_api = "responses"
env_key = "OPENAI_API_KEY"

[projects.%q]
trust_level = "trusted"

[tui]
animations = false
`, addr, f.ws))
	// --no-alt-screen keeps the transcript on the main screen, as in
	// Codex's own PTY tests. --no-daemon keeps the session in the TUI's
	// process: by default Codex 0.160 starts a shared app-server in a
	// session of its own, which outlives the TUI. airbag is the sandbox,
	// so Codex's own is off and asks for no approvals.
	agent := "exec env OPENAI_API_KEY=sk-mock codex --no-alt-screen --no-daemon --dangerously-bypass-approvals-and-sandbox"
	tm := Start(t, 120, 36, f.env(), f.ws, f.run("sh", "-c", mock+agent)...)

	tm.WaitFor(`mock-model`, 60*time.Second)
	tm.Snap("01-ready")

	// Codex takes a burst of keys for a paste and holds Enter back for
	// a moment after one: the keys go one at a time, and WaitFor's
	// settle leaves a gap before Enter.
	tm.TypeSlow("do the task")
	tm.WaitFor(`do the task`, 10*time.Second)
	tm.Send("\r")
	tm.WaitFor(`(?s)Ran echo from-codex > codex\.txt.*• done`, 30*time.Second)
	tm.Snap("02-done")

	tm.Send("\x03") // with an empty composer, Codex quits
	code := tm.Wait(30 * time.Second)
	tm.WaitFor(`codex resume`, 5*time.Second)
	if f.airbag != "" {
		tm.WaitFor(`airbag: session s-[0-9a-f]+ ended \(exit 0\)`, 5*time.Second)
	}
	tm.Snap("03-exit")
	if code != 0 {
		t.Errorf("exit status %d, want 0", code)
	}
	f.checkWrote("codex.txt")
}
