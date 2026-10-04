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
	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/steps"
)

// SocketInSandbox is where the control socket is mounted for the agent.
const SocketInSandbox = "/run/airbag/ctl.sock"

type Server struct {
	Box   *outbox.Box
	Log   *effects.Log
	Steps *steps.Tracker
}

func (s *Server) Serve(l net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /intent", s.intent)
	mux.HandleFunc("POST /hook/{agent}/{event}", s.hook)
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
	case "PostToolUse", "PostToolUseFailure":
		if s.Steps != nil {
			s.Steps.Record(p.ToolName, summary, p.ToolUseID)
		}
	}
	_, _ = w.Write([]byte("{}"))
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
