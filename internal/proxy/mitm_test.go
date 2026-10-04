package proxy

import (
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/getjump/airbag/internal/creds"
	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/policy"
)

// echo is a real TLS server that records the Authorization it got and
// sends it back, gzipped when asked: a host that echoes requests.
func echo(t *testing.T) (*httptest.Server, func() string) {
	var mu sync.Mutex
	var got string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Get("Authorization") + " q=" + r.URL.Query().Get("token")
		mu.Unlock()
		w.Header().Set("X-Seen", r.Header.Get("Authorization"))
		body := "you sent: " + got + "\n"
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = io.WriteString(gz, body)
			_ = gz.Close()
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, func() string { mu.Lock(); defer mu.Unlock(); return got }
}

func mitmProxy(t *testing.T, upstream *httptest.Server, rules string) (*http.Client, *creds.Live, string) {
	t.Helper()
	hostport := upstream.Listener.Addr().String()
	live := &creds.Live{Name: "demo", Hosts: []string{hostport}, Value: "ghp_RealSecretValue0123456789abcdef"}
	live.Placeholder = creds.Placeholder(live.Value)
	log, path := newLog(t)
	p := New(Allowlist{hostport}, log)
	p.Upstream = func(*url.URL) (*url.URL, error) { return nil, nil }
	p.Creds = creds.Set{live}
	ca, err := NewCA(live.Hosts)
	if err != nil {
		t.Fatal(err)
	}
	p.CA = ca
	p.UpstreamRoots = x509.NewCertPool()
	p.UpstreamRoots.AddCert(upstream.Certificate())
	if rules != "" {
		ws, dir := t.TempDir(), t.TempDir()
		_ = os.WriteFile(filepath.Join(ws, "airbag.yaml"), []byte(rules), 0o644)
		pol, err := policy.Load(ws, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		p.Gate = policy.NewGate(pol, dir)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() { _ = p.Serve(l) }()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.PEM)
	pu, _ := url.Parse("http://" + l.Addr().String())
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: roots}}}
	return c, live, path
}

func TestInterceptSubstitutesAndMasks(t *testing.T) {
	up, got := echo(t)
	c, live, logPath := mitmProxy(t, up, "")
	for _, gz := range []bool{false, true} {
		req, _ := http.NewRequest("GET", up.URL+"/repos/x?token="+live.Placeholder, nil)
		req.Header.Set("Authorization", "Bearer "+live.Placeholder)
		if gz {
			req.Header.Set("Accept-Encoding", "gzip") // the client then unpacks it itself
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r := io.Reader(resp.Body)
		if resp.Header.Get("Content-Encoding") == "gzip" {
			r, _ = gzip.NewReader(resp.Body)
		}
		body, _ := io.ReadAll(r)
		resp.Body.Close()
		if want := "Bearer " + live.Value + " q=" + live.Value; got() != want {
			t.Fatalf("upstream got %q, want %q", got(), want)
		}
		if strings.Contains(string(body), live.Value) || strings.Contains(resp.Header.Get("X-Seen"), live.Value) {
			t.Fatalf("the value reached the client: %q %q", body, resp.Header.Get("X-Seen"))
		}
		if !strings.Contains(string(body), live.Placeholder) {
			t.Fatalf("body %q", body)
		}
	}
	effs, _ := effects.Read(logPath)
	var seen bool
	for _, e := range effs {
		if e.Kind == "http.request" && strings.HasPrefix(e.Target, "GET ") && strings.HasSuffix(e.Target, "/repos/x") && e.Reason == "demo" {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("request not logged with its method and path: %+v", effs)
	}
}

// Basic credentials carry the placeholder inside base64.
func TestInterceptBasic(t *testing.T) {
	up, got := echo(t)
	c, live, _ := mitmProxy(t, up, "")
	req, _ := http.NewRequest("GET", up.URL+"/", nil)
	req.SetBasicAuth("x-access-token", live.Placeholder)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	want := &http.Request{Header: http.Header{}}
	want.SetBasicAuth("x-access-token", live.Value)
	if !strings.HasPrefix(got(), want.Header.Get("Authorization")) {
		t.Fatalf("upstream got %q", got())
	}
}

// Rules see each request with its method; a deny stops it here.
func TestInterceptPolicy(t *testing.T) {
	up, got := echo(t)
	c, live, _ := mitmProxy(t, up, `
rules:
  - name: read-only
    when: effect.kind == "http.request" && effect.detail != "GET"
    verdict: deny
    message: only reads
`)
	req, _ := http.NewRequest("POST", up.URL+"/repos/x/issues", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+live.Placeholder)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "only reads") || got() != "" {
		t.Fatalf("POST got through: %d %q, upstream saw %q", resp.StatusCode, body, got())
	}
}

// The CA can vouch only for the bound hosts.
func TestCANameConstraints(t *testing.T) {
	ca, err := NewCA([]string{"api.github.com"})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.PEM)
	for host, ok := range map[string]bool{"api.github.com": true, "evil.example": false} {
		leaf, err := ca.leaf(host)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(leaf.Certificate[0])
		_, err = cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: host})
		if (err == nil) != ok {
			t.Fatalf("%s: verify err %v, want ok=%v", host, err, ok)
		}
	}
}
