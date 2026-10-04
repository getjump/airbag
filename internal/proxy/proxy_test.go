package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/effects"
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
	p := New(Allowlist{"127.0.0.1"}, log)
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
	p := New(Allowlist{"127.0.0.1", "localhost"}, log)
	p.Upstream = func(*url.URL) (*url.URL, error) { return nil, nil }
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
