// Package agents knows how airbag plugs into specific coding agents.
package agents

import (
	"encoding/json"
	"strings"
)

// HookCommand is how agents call back into airbag from inside the sandbox.
const HookCommand = "/run/airbag/bin/airbag hook"

// ClaudeManagedSettingsDir is read by Claude Code on Linux; files there
// are merged into the managed policy tier, which user and project
// settings cannot disable.
const ClaudeManagedSettingsDir = "/etc/claude-code/managed-settings.d"

// ClaudeManagedSettings registers airbag's hooks for every tool call.
// Hooks are context, not enforcement: Claude Code lets a call through
// when a hook fails or times out, so the sandbox stays the boundary.
func ClaudeManagedSettings() []byte {
	hook := func(event string) []map[string]any {
		return []map[string]any{{
			"matcher": "*",
			"hooks": []map[string]any{{
				"type":    "command",
				"command": HookCommand + " claude " + event,
				"timeout": 30,
			}},
		}}
	}
	b, _ := json.MarshalIndent(map[string]any{ //nolint:errchkjson // strings and numbers only, which json always encodes
		"hooks": map[string]any{
			"PreToolUse":         hook("PreToolUse"),
			"PostToolUse":        hook("PostToolUse"),
			"PostToolUseFailure": hook("PostToolUseFailure"),
		},
	}, "", "  ")
	return b
}

// HookPayload is the part of a tool hook event airbag reads.
type HookPayload struct {
	Event     string          `json:"hook_event_name"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	ToolUseID string          `json:"tool_use_id"`
}

// ToolSummary is a one-line description of a tool call for the review.
func ToolSummary(tool string, input json.RawMessage) string {
	var in map[string]any
	_ = json.Unmarshal(input, &in)
	str := func(k string) string {
		s, _ := in[k].(string)
		return s
	}
	var s string
	switch tool {
	case "Bash":
		s = str("command")
	case "Edit", "MultiEdit", "Write", "Read", "NotebookEdit":
		s = str("file_path")
		if s == "" {
			s = str("notebook_path")
		}
	case "WebFetch":
		s = str("url")
	case "WebSearch":
		s = str("query")
	case "Grep", "Glob":
		s = str("pattern")
	default:
		if c, ok := ShellCommand(tool, in); ok {
			s = c
			break
		}
		for _, k := range []string{"cmd", "command", "file_path", "path", "url", "query"} {
			if s = str(k); s != "" {
				break
			}
		}
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 100 {
		s = s[:97] + "..."
	}
	return s
}
