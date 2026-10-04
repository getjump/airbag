// Package proxy is the only way out of the sandbox: an HTTP proxy that
// lets through CONNECT and plain HTTP requests to allowlisted hosts.
// It sees hosts, not request bodies (no TLS interception in v0).
package proxy

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/models"
	"github.com/getjump/airbag/internal/policy"
)

// DefaultAllow covers model APIs and package registries.
var DefaultAllow = []string{
	"api.anthropic.com", "*.anthropic.com", "claude.ai", "*.claude.ai", "*.claude.com",
	"api.openai.com", "auth.openai.com", "chatgpt.com", "*.chatgpt.com",
	"proxy.golang.org", "sum.golang.org",
	"registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
}

type Allowlist []string

func (a Allowlist) Allows(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range a {
		p = strings.ToLower(p)
		if p == host || (strings.HasPrefix(p, "*.") && strings.HasSuffix(host, p[1:])) {
			return true
		}
	}
	return false
}

type Proxy struct {
	Allow Allowlist
	Log   *effects.Log
	// Gate applies policy rules on top of the allowlist (optional).
	Gate *policy.Gate
	// Upstream returns the host's own proxy for a target, if any, so
	// airbag works behind a corporate or sandbox proxy.
	Upstream func(*url.URL) (*url.URL, error)
}

func New(allow Allowlist, log *effects.Log) *Proxy {
	return &Proxy{Allow: allow, Log: log, Upstream: func(u *url.URL) (*url.URL, error) {
		return http.ProxyFromEnvironment(&http.Request{URL: u})
	}}
}

func (p *Proxy) Serve(l net.Listener) error {
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 30 * time.Second}
	return srv.Serve(l)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	if r.Method == http.MethodConnect {
		host, _, _ = net.SplitHostPort(r.Host)
	}
	target := r.Host
	if !p.Allow.Allows(host) && (p.Gate == nil || !p.Gate.AllowsHost(host)) {
		p.Log.Add(effects.Effect{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "host not in allowlist"})
		http.Error(w, "airbag: egress to "+host+" denied by policy (host not in allowlist)", http.StatusForbidden)
		return
	}
	if p.Gate != nil {
		_, port, _ := net.SplitHostPort(target)
		if d, id := p.Gate.Check(policy.Input{Effect: models.Effect{Kind: "net.connect", Target: host, Detail: port}}); d.Verdict != policy.Allow {
			p.Log.Add(effects.Effect{Kind: "net.egress", Target: target, Verdict: d.Verdict, Reason: d.Rule})
			http.Error(w, policy.Explain(d, id), http.StatusForbidden)
			return
		}
	}
	p.Log.Add(effects.Effect{Kind: "net.egress", Target: target, Verdict: "allow"})
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	p.forward(w, r)
}

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	up, err := p.dial(r.Host)
	if err != nil {
		http.Error(w, "airbag: "+err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	pipe(conn, buf.Reader, up)
}

// dial opens a TCP stream to hostport, through the host's upstream
// proxy when the host environment has one.
func (p *Proxy) dial(hostport string) (net.Conn, error) {
	pu, err := p.Upstream(&url.URL{Scheme: "https", Host: hostport})
	if err != nil {
		return nil, err
	}
	if pu == nil {
		return net.DialTimeout("tcp", hostport, 15*time.Second)
	}
	c, err := net.DialTimeout("tcp", pu.Host, 15*time.Second)
	if err != nil {
		return nil, err
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: hostport}, Host: hostport, Header: http.Header{}}
	if pu.User != nil {
		req.Header.Set("Proxy-Authorization", "Basic "+basicAuth(pu.User))
	}
	if err := req.Write(c); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		c.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, &url.Error{Op: "CONNECT", URL: hostport, Err: errStatus(resp.Status)}
	}
	if br.Buffered() > 0 {
		return &bufConn{Conn: c, r: br}, nil
	}
	return c, nil
}

var transport = &http.Transport{Proxy: http.ProxyFromEnvironment}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	out := r.Clone(r.Context())
	out.RequestURI = ""
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"} {
		out.Header.Del(h)
	}
	resp, err := transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "airbag: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func pipe(a net.Conn, ar io.Reader, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(b, ar); closeWrite(b) }()
	go func() { defer wg.Done(); _, _ = io.Copy(a, b); closeWrite(a) }()
	wg.Wait()
	a.Close()
	b.Close()
}

func closeWrite(c net.Conn) {
	type cw interface{ CloseWrite() error }
	if x, ok := c.(cw); ok {
		_ = x.CloseWrite()
	} else if bc, ok := c.(*bufConn); ok {
		closeWrite(bc.Conn)
	}
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type errStatus string

func (e errStatus) Error() string { return "upstream proxy: " + string(e) }

func basicAuth(u *url.Userinfo) string {
	pw, _ := u.Password()
	return base64.StdEncoding.EncodeToString([]byte(u.Username() + ":" + pw))
}
