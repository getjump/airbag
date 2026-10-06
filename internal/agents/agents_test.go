package agents

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestShellCommand(t *testing.T) {
	for _, c := range []struct{ tool, in, want string }{
		{"Bash", `{"command":"ls -la"}`, "ls -la"},
		{"exec_command", `{"cmd":"git push"}`, "git push"},
		{"shell", `{"command":["bash","-lc","echo hi > a"]}`, "echo hi > a"},
		{"shell", `{"command":["rg","-n","x"]}`, "rg -n x"},
		{"Write", `{"file_path":"a"}`, ""},
	} {
		var in map[string]any
		_ = json.Unmarshal([]byte(c.in), &in)
		if got, _ := ShellCommand(c.tool, in); got != c.want {
			t.Errorf("ShellCommand(%s, %s) = %q, want %q", c.tool, c.in, got, c.want)
		}
	}
}

func TestCodexRequirements(t *testing.T) {
	s := string(CodexRequirements())
	for _, want := range []string{"allow_login_shell = false", "hooks = true", "[[hooks.PreToolUse]]", `command = "/run/airbag/bin/airbag hook codex PostToolUse"`} {
		if !strings.Contains(s, want) {
			t.Errorf("requirements lack %q:\n%s", want, s)
		}
	}
}
