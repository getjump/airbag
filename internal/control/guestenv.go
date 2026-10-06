package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// maxGuestEnv bounds the environment a guest takes: more than the kernel
// lets one exec pass.
const maxGuestEnv = 4 << 20

// guestEnv holds the environment an optional runtime's guest starts its
// agent with. It holds API keys and --pass-env values, so it is handed
// over the control channel and never written to the staged rootfs or a
// microVM's image, where a run cut short by SIGKILL or a crash would
// leave it on disk.
type guestEnv struct {
	mu      sync.Mutex
	env     []string
	offered bool
}

// OfferGuestEnv makes env the one answer to the guest's request for it.
func (s *Server) OfferGuestEnv(env []string) {
	s.guest.mu.Lock()
	defer s.guest.mu.Unlock()
	s.guest.env, s.guest.offered = env, true
}

// takeGuestEnv answers once: the guest's helper takes the environment
// before it starts the agent, which shares this socket, so no later
// caller gets it from here.
func (s *Server) takeGuestEnv(w http.ResponseWriter, _ *http.Request) {
	s.guest.mu.Lock()
	env, offered := s.guest.env, s.guest.offered
	s.guest.env, s.guest.offered = nil, false
	s.guest.mu.Unlock()
	if !offered {
		http.Error(w, "no environment to take", http.StatusGone)
		return
	}
	if env == nil {
		env = []string{}
	}
	writeJSON(w, env)
}

// GuestEnv takes the agent's environment from the host, through the
// control socket at socket. It runs in an optional runtime's guest.
func GuestEnv(socket string) ([]string, error) {
	c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true,
	}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://airbag/guest/env", http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("take the agent's environment: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("take the agent's environment: %s", strings.TrimSpace(string(msg)))
	}
	var env []string
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxGuestEnv+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("take the agent's environment: %w", err)
	case len(b) > maxGuestEnv:
		return nil, errors.New("take the agent's environment: more than 4 MiB")
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("take the agent's environment: %w", err)
	}
	return env, nil
}
