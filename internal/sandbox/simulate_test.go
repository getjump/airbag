package sandbox

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/session"
)

// Stubs alone, without a credential, give the session a CA that the
// agent's tools are pointed at, and the proxy answers from them.
func TestHostServicesSimulate(t *testing.T) {
	s, _, ep := hostFixture(t)
	cfg := filepath.Join(s.Home, ".config", "airbag", "airbag.yaml")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("simulate:\n  - name: charge\n    match: {host: api.pay.test, path: /v1/charges}\n    respond: {status: 201, body: ok}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(s.Workspace, s.Home)
	if err != nil {
		t.Fatal(err)
	}
	h, err := startHostServices(s, nil, pol, ep)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	saved, err := session.Load(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(saved.Simulated, []string{"api.pay.test"}) {
		t.Fatalf("session records %v", saved.Simulated)
	}
	env := credEnv(saved, "/run/airbag/ca.pem", "/run/airbag/ca-bundle.pem")
	if env["NODE_EXTRA_CA_CERTS"] != "/run/airbag/ca.pem" || env["SSL_CERT_FILE"] != "/run/airbag/ca-bundle.pem" || env["REQUESTS_CA_BUNDLE"] != "/run/airbag/ca-bundle.pem" {
		t.Fatalf("CA environment %v", env)
	}
	if _, ok := env["AIRBAG_PLACEHOLDERS"]; ok {
		t.Fatal("placeholders named without a credential")
	}
	pem, err := os.ReadFile(s.CACert())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	c := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: h.ProxyAddr.String()}),
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}}
	defer c.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.pay.test/v1/charges", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || string(b) != "ok" {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
}

func TestCredEnvWithoutCredentialsOrStubs(t *testing.T) {
	if env := credEnv(&session.Session{}, "/ca.pem", "/bundle.pem"); len(env) != 0 {
		t.Fatalf("CA environment with nothing to trust it for: %v", env)
	}
}
