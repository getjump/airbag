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

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/outbox"
)

// SocketInSandbox is where the control socket is mounted for the agent.
const SocketInSandbox = "/run/airbag/ctl.sock"

type Server struct {
	Box *outbox.Box
	Log *effects.Log
}

func (s *Server) Serve(l net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /intent", s.intent)
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

// Submit is called from inside the sandbox.
func Submit(in outbox.Intent) (outbox.Intent, error) {
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", SocketInSandbox)
		},
	}}
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
