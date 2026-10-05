package sandbox

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/outbox"
)

func hostFixture(t *testing.T) (*session.Session, *policy.Policy, hostEndpoints) {
	t.Helper()
	// Short sockets also let the same lifecycle test run on macOS.
	root, err := os.MkdirTemp("/tmp", "ab-host-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	probe, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", filepath.Join(root, "probe.sock"))
	if err != nil {
		if errors.Is(err, syscall.EPERM) && os.Getenv("CI") == "" {
			t.Skip("this runner refuses Unix sockets; CI runs the real host lifecycle")
		}
		t.Fatal(err)
	}
	probe.Close()
	t.Setenv("AIRBAG_HOME", filepath.Join(root, "sessions"))
	ws, home := filepath.Join(root, "ws"), filepath.Join(root, "home")
	for _, dir := range []string{ws, home} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s, err := session.Create(session.Meta{Workspace: ws, Home: home, Cwd: ws})
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(ws, home)
	if err != nil {
		t.Fatal(err)
	}
	return s, p, hostEndpoints{ProxyNetwork: "tcp", ProxyAddress: "127.0.0.1:0", ControlRoot: ws}
}

func TestHostServicesStopAndResume(t *testing.T) {
	s, pol, ep := hostFixture(t)
	for range 2 {
		h, err := startHostServices(s, nil, pol, ep)
		if err != nil {
			t.Fatal(err)
		}
		address := h.ProxyAddr.String()
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", s.ControlSock())
		}}
		client := &http.Client{Transport: transport}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://control/taint", strings.NewReader(`{"file":".env","exe":"fixture"}`))
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		transport.CloseIdleConnections()
		if response.StatusCode != http.StatusOK || h.Gate.Tainted() != ".env" {
			t.Fatal("host control/label authority did not operate")
		}
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		if c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", address); err == nil {
			c.Close()
			t.Fatal("proxy still accepted connections after close")
		}
	}
	rows, err := effects.Read(s.EffectsPath())
	if err != nil || len(rows) != 2 {
		t.Fatal("host audit did not survive close and resume", rows, err)
	}
	b, err := outbox.Open(s.EffectsPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHostStartupUnwindsListener(t *testing.T) {
	s, pol, ep := hostFixture(t)
	// An occupied directory is not a usable Unix listener. Failure occurs after the
	// proxy acquired its listener and storage, so cleanup must unwind both.
	if err := os.Mkdir(s.ControlSock(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.ControlSock(), "occupied"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ep.ProxyAddress = l.Addr().String()
	l.Close()
	if h, err := startHostServices(s, nil, pol, ep); err == nil || h != nil {
		t.Fatal("startup accepted unusable control socket")
	}
	l, err = (&net.ListenConfig{}).Listen(t.Context(), "tcp", ep.ProxyAddress)
	if err != nil {
		t.Fatal("failed startup leaked its proxy listener", err)
	}
	l.Close()
}
