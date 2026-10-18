package agents

import (
	"fmt"
	"strings"
)

// CodexRequirementsPath is Codex's managed configuration on Linux.
// Hooks defined there are trusted by policy, without per-user review.
const CodexRequirementsPath = "/etc/codex/requirements.toml"

// CodexRequirements turns on hooks and registers airbag's. As with
// Claude Code, hooks only add context; a failed hook lets the call
// through, so the sandbox stays the boundary.
func CodexRequirements() []byte {
	var b strings.Builder
	b.WriteString("# Written by airbag for this sandbox.\nallow_login_shell = false\n[features]\nhooks = true\n")
	for _, ev := range []string{"PreToolUse", "PostToolUse"} {
		fmt.Fprintf(&b, "\n[[hooks.%s]]\nmatcher = \"*\"\n[[hooks.%s.hooks]]\ntype = \"command\"\ncommand = %q\ntimeout = 30\n",
			ev, ev, HookCommand+" codex "+ev)
	}
	return []byte(b.String())
}

// ShellCommand extracts the shell command from a tool call of either
// agent: Claude's Bash {command}, Codex's exec_command {cmd} or shell
// {command: [argv...]}.
func ShellCommand(tool string, in map[string]any) (string, bool) {
	switch tool {
	case "Bash":
		s, ok := in["command"].(string)
		return s, ok
	case "exec_command", "local_shell":
		if s, ok := in["cmd"].(string); ok {
			return s, true
		}
	case "shell", "container.exec":
	default:
		return "", false
	}
	switch c := in["command"].(type) {
	case string:
		return c, true
	case []any:
		parts := make([]string, 0, len(c))
		for _, p := range c {
			s, _ := p.(string)
			parts = append(parts, s)
		}
		// ["bash", "-lc", "script"]: the script is what runs.
		if len(parts) == 3 && (parts[1] == "-lc" || parts[1] == "-c") {
			return parts[2], true
		}
		return strings.Join(parts, " "), true
	}
	return "", false
}
