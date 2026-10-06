package control

import (
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The guest's helper takes the agent's environment once, before it
// starts the agent, which shares the socket: a second request, the
// agent's, gets nothing, and so does one made before the host offers it.
func TestGuestEnvIsTakenOnce(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "ctl.sock")
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	done := make(chan struct{})
	go func() { _ = s.Serve(l); close(done) }()
	defer func() { l.Close(); <-done }()

	if env, err := GuestEnv(sock); err == nil {
		t.Fatalf("an environment taken before it was offered: %q", env)
	}
	want := []string{"HOME=/home/agent", "CHECK_TOKEN=placeholder", "PASSED=value with = and spaces"}
	s.OfferGuestEnv(want)
	env, err := GuestEnv(sock)
	if err != nil || !slices.Equal(env, want) {
		t.Fatalf("got %q %v, want %q", env, err, want)
	}
	if env, err := GuestEnv(sock); err == nil || !strings.Contains(err.Error(), "no environment") {
		t.Fatalf("taken twice: %q %v", env, err)
	}
	// An empty environment is still one answer, not an error.
	s.OfferGuestEnv(nil)
	if env, err := GuestEnv(sock); err != nil || len(env) != 0 {
		t.Fatalf("empty environment: %q %v", env, err)
	}
}
