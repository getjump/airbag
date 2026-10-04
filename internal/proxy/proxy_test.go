package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/policy"
)

func TestAllowlist(t *testing.T) {
	a := Allowlist{"api.anthropic.com", "*.example.com"}
	for host, want := range map[string]bool{
		"api.anthropic.com":  true,
		"API.Anthropic.com.": true,
		"evil.com":           false,
		"a.example.com":      true,
		"example.com":        false,
		"anthropic.com":      false,
		"xapi.anthropic.com": false,
	} {
		if got := a.Allows(host); got != want {
			t.Errorf("Allows(%q) = %v, want %v", host, got, want)
		}
	}
}

func newLog(t *testing.T) (*effects.Log, string) {
	p := filepath.Join(t.TempDir(), "effects.jsonl")
	l, err := effects.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, p
}

func TestDenyIsLogged(t *testing.T) {
	log, path := newLog(t)
	p := New(Allowlist{"api.anthropic.com"}, log)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, &http.Request{Method: http.MethodConnect, Host: "paste.example.net:443", URL: &url.URL{Host: "paste.example.net:443"}})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "denied by policy") {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	effs, _ := effects.Read(path)
	if len(effs) != 1 || effs[0].Verdict != "deny" || effs[0].Target != "paste.example.net:443" {
		t.Fatalf("effects = %+v", effs)
	}
}

// A CONNECT to an allowed host is tunnelled byte for byte.
func TestConnectTunnel(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err == nil {
			_, _ = io.Copy(c, c)
			c.Close()
		}
	}()

	log, _ := newLog(t)
	p := New(Allowlist{"127.0.0.1:*"}, log)
	p.Upstream = func(*url.URL) (*url.URL, error) { return nil, nil }
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { _ = p.Serve(l) }()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	target := echo.Addr().String()
	_, _ = c.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	_, _ = c.Write([]byte("ping\n"))
	line, _ := br.ReadString('\n')
	if line != "ping\n" {
		t.Fatalf("echo = %q", line)
	}
}

func TestCutOnTaint(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	log, path := newLog(t)
	p := New(Allowlist{"127.0.0.1:*", "localhost:*"}, log)
	p.Upstream = func(*url.URL) (*url.URL, error) { return nil, nil }
	p.forbid = func(netip.Addr) string { return "" } // localhost stands in for a remote host
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { _ = p.Serve(l) }()

	open := func(host string) (*bufio.Reader, net.Conn) {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, port, _ := net.SplitHostPort(echo.Addr().String())
		target := host + ":" + port
		_, _ = c.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
		br := bufio.NewReader(c)
		if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 200 {
			t.Fatalf("CONNECT %s: %v %v", host, resp, err)
		}
		return br, c
	}
	// A tunnel to a host the session may no longer reach once tainted,
	// and one to a host it keeps (standing in for a model API).
	cutR, cutC := open("127.0.0.1")
	defer cutC.Close()
	keepR, keepC := open("localhost")
	defer keepC.Close()

	p.Cut(Allowlist{"localhost"}, "secret-taint")

	_, _ = cutC.Write([]byte("secret\n"))
	if line, err := cutR.ReadString('\n'); err == nil {
		t.Fatalf("tunnel still carries data after Cut: %q", line)
	}
	_, _ = keepC.Write([]byte("ping\n"))
	if line, _ := keepR.ReadString('\n'); line != "ping\n" {
		t.Fatalf("kept tunnel broken: %q", line)
	}
	log.Close()
	effs, _ := effects.Read(path)
	var cuts []string
	for _, e := range effs {
		if e.Verdict == "cut" {
			cuts = append(cuts, e.Target+" "+e.Reason)
		}
	}
	if len(cuts) != 1 || !strings.HasPrefix(cuts[0], "127.0.0.1:") || !strings.HasSuffix(cuts[0], "secret-taint") {
		t.Fatalf("cut effects = %v", cuts)
	}
}

func TestForbidden(t *testing.T) {
	for addr, bad := range map[string]bool{
		"127.0.0.1": true, "127.1.2.3": true, "::1": true, "::ffff:127.0.0.1": true,
		"0.0.0.0": true, "0.1.2.3": true, "::": true,
		"169.254.169.254": true, "fe80::1": true, "fd00:ec2::254": true, "100.100.100.200": true,
		"224.0.0.1": true, "255.255.255.255": true, "64:ff9b::7f00:1": true,
		"93.184.215.14": false, "10.1.2.3": false, "192.168.77.1": false, "2606:4700::1111": false,
	} {
		if got := forbidden(netip.MustParseAddr(addr)) != ""; got != bad {
			t.Errorf("forbidden(%s) = %v, want %v", addr, got, bad)
		}
	}
}

func TestAllowsPort(t *testing.T) {
	a := Allowlist{"example.com", "*.corp.test:8443", "db.test:*", "[::1]:5432"}
	for _, c := range []struct {
		host, port string
		want       bool
	}{
		{"example.com", "443", true}, {"example.com", "80", true}, {"example.com", "8443", false},
		{"git.corp.test", "8443", true}, {"git.corp.test", "443", true}, {"git.corp.test", "22", false},
		{"db.test", "5432", true}, {"::1", "5432", true}, {"other.test", "443", false},
	} {
		if got := a.AllowsPort(c.host, c.port); got != c.want {
			t.Errorf("AllowsPort(%s, %s) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
	if !a.explicitIP("::1") || a.explicitIP("example.com") || a.explicitIP("127.0.0.1") {
		t.Error("explicitIP")
	}
}

// A name allowed by the user that resolves to the host itself is
// refused at connect time, and a port beyond 80 and 443 needs an entry
// that names it.
func TestGuard(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	log, path := newLog(t)
	p := New(Allowlist{"localhost:*", "example.test"}, log)
	p.Upstream = func(*url.URL) (*url.URL, error) { return nil, nil }
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { _ = p.Serve(l) }()

	connect := func(target string) (int, string) {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	if code, body := connect("localhost:" + port); code != 403 || !strings.Contains(body, "loopback") {
		t.Errorf("localhost: %d %q", code, body)
	}
	if code, body := connect("example.test:8443"); code != 403 || !strings.Contains(body, "port 8443") {
		t.Errorf("example.test:8443: %d %q", code, body)
	}
	log.Close()
	effs, _ := effects.Read(path)
	var reasons []string
	for _, e := range effs {
		if e.Verdict == "deny" {
			reasons = append(reasons, e.Reason)
		}
	}
	if strings.Join(reasons, ",") != "address: loopback,port not allowed" {
		t.Errorf("deny reasons = %v", reasons)
	}
}

// Rules, the allowlist and the log see one spelling of the host: a rule
// on api.example also stops "API.EXAMPLE.", and a name that is not
// ASCII is refused before any check.
func TestHostSpelledOneWay(t *testing.T) {
	ws, dir := t.TempDir(), t.TempDir()
	_ = os.WriteFile(filepath.Join(ws, "airbag.yaml"), []byte(`
rules:
  - name: no-api
    when: effect.kind == "net.connect" && effect.target == "api.example"
    verdict: deny
    message: not this host
`), 0o644)
	pol, err := policy.Load(ws, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log, path := newLog(t)
	p := New(Allowlist{"api.example"}, log)
	p.Upstream = func(*url.URL) (*url.URL, error) { return nil, nil }
	p.Gate = policy.NewGate(pol, dir)
	for _, c := range []struct {
		hostport string
		code     int
		body     string
	}{
		{"API.EXAMPLE.:443", http.StatusForbidden, "not this host"},
		{"Api.Example:443", http.StatusForbidden, "not this host"},
		{"api.example..:443", http.StatusBadRequest, "empty label"},
		{".api.example:443", http.StatusBadRequest, "empty label"},
		{"api..example:443", http.StatusBadRequest, "empty label"},
		{"ap\u0130.example:443", http.StatusBadRequest, "ASCII"},
		{"\u212Aite.example:443", http.StatusBadRequest, "ASCII"},
	} {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, &http.Request{Method: http.MethodConnect, Host: c.hostport, URL: &url.URL{Host: c.hostport}})
		if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.body) {
			t.Errorf("CONNECT %q: %d %q, want %d %q", c.hostport, rec.Code, rec.Body.String(), c.code, c.body)
		}
	}
	effs, _ := effects.Read(path)
	if len(effs) == 0 || effs[0].Target != "api.example:443" {
		t.Fatalf("effects = %+v, want the first logged as api.example:443", effs)
	}
}

// A plain HTTP request is logged, checked and sent with the same
// spelling; a CONNECT without a port keeps what it named.
func TestPlainHTTPHostSpelledOneWay(t *testing.T) {
	var seen string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.Host }))
	t.Cleanup(up.Close)
	_, port, _ := net.SplitHostPort(up.Listener.Addr().String())
	log, path := newLog(t)
	p := New(Allowlist{"127.0.0.1:*"}, log)
	p.Upstream = func(*url.URL) (*url.URL, error) { return nil, nil }
	u, _ := url.Parse("http://127.0.0.1.:" + port + "/x")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, &http.Request{Method: "GET", Host: u.Host, URL: u, Header: http.Header{}})
	if rec.Code != http.StatusOK || seen != "127.0.0.1:"+port {
		t.Fatalf("%d %q, upstream saw Host %q", rec.Code, rec.Body.String(), seen)
	}
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, &http.Request{Method: http.MethodConnect, Host: "api.example", URL: &url.URL{Host: "api.example"}})
	effs, _ := effects.Read(path)
	if len(effs) < 2 || effs[0].Target != "127.0.0.1:"+port || effs[len(effs)-1].Target != "api.example" {
		t.Fatalf("effects = %+v", effs)
	}
}
