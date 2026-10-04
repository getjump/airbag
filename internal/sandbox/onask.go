package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/session"
)

// AskEvent is what an on_ask command gets on stdin.
type AskEvent struct {
	Session   string `json:"session"`
	Workspace string `json:"workspace"`
	ID        string `json:"id"`
	Rule      string `json:"rule"`
	What      string `json:"what"`
	Message   string `json:"message,omitempty"`
	Approve   string `json:"approve"` // the commands that decide it
	Deny      string `json:"deny"`
}

func NewAskEvent(s *session.Session, r policy.Request) AskEvent {
	ref := s.ID + "/" + r.ID
	return AskEvent{Session: s.ID, Workspace: s.Workspace, ID: r.ID, Rule: r.Rule, What: r.What, Message: r.Message,
		Approve: "airbag approve " + ref, Deny: "airbag deny " + ref}
}

// runOnAsk runs the user's on_ask command on the host. The request comes
// from what the agent did, so it is passed as data: JSON on stdin and
// AIRBAG_* variables, never spliced into a shell line. Output goes to
// the session's hooks.log, not to the terminal the agent draws on.
func runOnAsk(argv []string, r policy.Request, s *session.Session) {
	if len(argv) == 0 {
		return
	}
	ev := NewAskEvent(s, r)
	body, _ := json.Marshal(ev)
	name := argv[0]
	if rest, ok := strings.CutPrefix(name, "~/"); ok {
		name = filepath.Join(s.Home, rest)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, argv[1:]...)
	cmd.Stdin = bytes.NewReader(append(body, '\n'))
	cmd.Env = append(os.Environ(),
		"AIRBAG_SESSION="+ev.Session, "AIRBAG_WORKSPACE="+ev.Workspace, "AIRBAG_ASK_ID="+ev.ID,
		"AIRBAG_ASK_REF="+ev.Session+"/"+ev.ID, "AIRBAG_ASK_RULE="+ev.Rule,
		"AIRBAG_ASK_WHAT="+ev.What, "AIRBAG_ASK_MESSAGE="+ev.Message)
	if f, err := os.OpenFile(filepath.Join(s.Dir, "hooks.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		defer f.Close()
		cmd.Stdout, cmd.Stderr = f, f
	}
	_ = cmd.Run()
}
