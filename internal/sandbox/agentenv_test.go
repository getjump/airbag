package sandbox

import (
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

func TestAgentTempDirectory(t *testing.T) {
	t.Setenv("CLAUDE_CODE_TMPDIR", "/tmp/host-claude-temp")
	s := &session.Session{Meta: session.Meta{ID: "s-test"}}
	env := agentEnvFor(s, "127.0.0.1:12345", "/session/bin", "/session/private-temp", nil)
	var got []string
	for _, entry := range env {
		if value, ok := strings.CutPrefix(entry, "CLAUDE_CODE_TMPDIR="); ok {
			got = append(got, value)
		}
	}
	if len(got) != 1 || got[0] != "/session/private-temp" {
		t.Fatalf("CLAUDE_CODE_TMPDIR=%q, want one /session/private-temp entry", got)
	}
}
