// Package control is the channel from inside the sandbox to the host
// side of airbag: the agent's shims report intents through it.
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/getjump/airbag/internal/agents"
	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/models"
	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/steps"
)

// SocketInSandbox is where the control socket is mounted for the agent.
const SocketInSandbox = "/run/airbag/ctl.sock"

type Server struct {
	Box   *outbox.Box
	Log   *effects.Log
	Steps *steps.Tracker
	Gate  *policy.Gate
}

func (s *Server) Serve(l net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /intent", s.intent)
	mux.HandleFunc("POST /hook/{agent}/{event}", s.hook)
	mux.HandleFunc("POST /exec", s.exec)
	mux.HandleFunc("POST /taint", s.taint)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(l)
}

func (s *Server) intent(w http.ResponseWriter, r *http.Request) {
	var in outbox.Intent
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if in.Kind != "git.push" {
		http.Error(w, "unsupported intent kind "+in.Kind, http.StatusBadRequest)
		return
	}
	if _, err := outbox.GitPush(in.Argv); err != nil {
		s.Log.Add(effects.Effect{Kind: "intent." + in.Kind, Target: fmt.Sprint(in.Argv), Verdict: "deny", Reason: err.Error()})
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	in, err := s.Box.Push(in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.Log.Add(effects.Effect{Kind: "intent." + in.Kind, Target: fmt.Sprint(in.Argv), Verdict: "defer", Reason: in.ID})
	_ = json.NewEncoder(w).Encode(in)
}

// hook receives agent hook events. Tool calls go to the effect log;
// the end of each call closes a step, so the review can tell which
// call changed which files.
func (s *Server) hook(w http.ResponseWriter, r *http.Request) {
	var p agents.HookPayload
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	agent, event := r.PathValue("agent"), r.PathValue("event")
	summary := agents.ToolSummary(p.ToolName, p.ToolInput)
	switch event {
	case "PreToolUse":
		if s.Steps != nil {
			s.Steps.Between()
		}
		s.Log.Add(effects.Effect{Kind: "tool.call", Target: p.ToolName + ": " + summary, Verdict: "allow", Reason: agent + " " + p.ToolUseID})
		// Tell the agent before the command runs; the shell shim checks
		// again for agents without hooks.
		if p.ToolName == "Bash" && agent == "claude" {
			var in struct {
				Command string `json:"command"`
			}
			_ = json.Unmarshal(p.ToolInput, &in)
			cmds, _ := models.Analyze(in.Command)
			for _, c := range cmds {
				if d, id := s.judge(c); d.Verdict != policy.Allow {
					s.Log.Add(effects.Effect{Kind: "tool.call", Target: p.ToolName + ": " + summary, Verdict: d.Verdict, Reason: d.Rule})
					_ = json.NewEncoder(w).Encode(map[string]any{"hookSpecificOutput": map[string]any{
						"hookEventName":            "PreToolUse",
						"permissionDecision":       "deny",
						"permissionDecisionReason": policy.Explain(d, id),
					}})
					return
				}
			}
		}
	case "PostToolUse", "PostToolUseFailure":
		if s.Steps != nil {
			s.Steps.Record(p.ToolName, summary, p.ToolUseID)
		}
	}
	_, _ = w.Write([]byte("{}"))
}

// Taint is reported by the secret filesystem when a process reads .env.
type Taint struct {
	File string `json:"file"`
	Exe  string `json:"exe"`
}

func (s *Server) taint(w http.ResponseWriter, r *http.Request) {
	var t Taint
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&t); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.Gate != nil {
		s.Gate.Taint(t.File)
	}
	s.Log.Add(effects.Effect{Kind: "secret.read", Target: t.File, Verdict: "taint", Reason: t.Exe})
	_, _ = w.Write([]byte("{}"))
}

// ReportTaint is called from the sandbox init process.
func ReportTaint(t Taint) {
	body, _ := json.Marshal(t)
	if resp, err := client(3*time.Second).Post("http://airbag/taint", "application/json", bytes.NewReader(body)); err == nil {
		resp.Body.Close()
	}
}

// Exec is what the shell shim reports before running a script.
type Exec struct {
	Shell      string           `json:"shell"`
	Script     string           `json:"script"`
	Commands   []models.Command `json:"commands"`
	ParseError string           `json:"parse_error,omitempty"`
}

func (s *Server) exec(w http.ResponseWriter, r *http.Request) {
	var e Exec
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&e); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if e.ParseError != "" {
		s.Log.Add(effects.Effect{Kind: "proc.exec", Target: clip(e.Script, 200), Verdict: "allow", Reason: "unparsed: " + e.ParseError})
	}
	verdict := Verdict{Verdict: policy.Allow}
	for _, c := range e.Commands {
		d, id := s.judge(c)
		var pred []string
		for _, ef := range c.Effects {
			pred = append(pred, ef.String())
		}
		s.Log.Add(effects.Effect{Kind: "proc.exec", Target: clip(strings.Join(c.Argv, " "), 200), Verdict: d.Verdict, Reason: d.Rule, Predict: pred})
		if d.Verdict != policy.Allow && verdict.Verdict == policy.Allow {
			verdict = Verdict{Verdict: d.Verdict, Message: policy.Explain(d, id)}
		}
	}
	_ = json.NewEncoder(w).Encode(verdict)
}

// Verdict is the answer to the shell shim and to PreToolUse hooks.
type Verdict struct {
	Verdict string `json:"verdict"`
	Message string `json:"message,omitempty"`
}

// judge runs every predicted effect of a command through the policy.
// The command itself is an effect too, so rules can match command lines.
func (s *Server) judge(c models.Command) (policy.Decision, string) {
	best, bestID := policy.Decision{Verdict: policy.Allow}, ""
	if s.Gate == nil || len(c.Argv) == 0 {
		return best, ""
	}
	all := append([]models.Effect{{Kind: "proc.exec", Target: c.Argv[0]}}, c.Effects...)
	for _, ef := range all {
		d, id := s.Gate.Check(policy.Input{Effect: ef, Argv: c.Argv})
		if d.Verdict == policy.Deny || (d.Verdict == policy.Ask && best.Verdict == policy.Allow) {
			best, bestID = d, id
		}
	}
	return best, bestID
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ReportExec is called by the shell shim inside the sandbox. Transport
// errors count as allow: the shim is a guide, the sandbox is the wall.
func ReportExec(e Exec) Verdict {
	body, _ := json.Marshal(e)
	v := Verdict{Verdict: policy.Allow}
	resp, err := client(3*time.Second).Post("http://airbag/exec", "application/json", bytes.NewReader(body))
	if err != nil {
		return v
	}
	defer resp.Body.Close()
	_ = json.NewDecoder(resp.Body).Decode(&v)
	return v
}

// Hook forwards a hook event from inside the sandbox.
func Hook(agent, event string, payload []byte) ([]byte, error) {
	resp, err := client(5*time.Second).Post("http://airbag/hook/"+agent+"/"+event, "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", SocketInSandbox)
		},
	}}
}

// Submit is called from inside the sandbox.
func Submit(in outbox.Intent) (outbox.Intent, error) {
	c := client(10 * time.Second)
	body, _ := json.Marshal(in)
	resp, err := c.Post("http://airbag/intent", "application/json", bytes.NewReader(body))
	if err != nil {
		return in, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return in, fmt.Errorf("%s", strings.TrimSpace(string(msg)))
	}
	return in, json.NewDecoder(resp.Body).Decode(&in)
}
