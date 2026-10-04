// Package proxy is the only way out of the sandbox: an HTTP proxy that
// lets through CONNECT and plain HTTP requests to allowlisted hosts.
// It sees hosts, not requests, except for the hosts a credential is
// bound to: for those it terminates TLS (mitm.go).
package proxy

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/getjump/airbag/internal/creds"
	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/models"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/taint"
)

// DefaultAllow covers model APIs.
var DefaultAllow = []string{
	"api.anthropic.com", "*.anthropic.com", "claude.ai", "*.claude.ai", "*.claude.com",
	"api.openai.com", "auth.openai.com", "chatgpt.com", "*.chatgpt.com",
}

// Registries are reached only by airbag's mirror, which fetches from the
// host side; the agent's package managers point at the mirror.
var Registries = Allowlist{
	"proxy.golang.org", "sum.golang.org",
	"registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
}

type Allowlist []string

// Allows reports whether host is allowed; an entry's port, if any, is
// checked by AllowsPort.
func (a Allowlist) Allows(host string) bool {
	host = creds.CanonHost(host)
	for _, p := range a {
		if h, _, err := net.SplitHostPort(p); err == nil {
			p = h
		}
		p = creds.CanonHost(p)
		if p == "" {
			continue // ":*", "." or "[]" names no host
		}
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
	// Mirror serves http://airbag.mirror/ (optional).
	Mirror http.Handler
	// Upstream returns the host's own proxy for a target, if any, so
	// airbag works behind a corporate or sandbox proxy.
	Upstream func(*url.URL) (*url.URL, error)
	// Creds are the credentials bound to hosts; with CA set, TLS to
	// those hosts is terminated here (mitm.go).
	Creds creds.Set
	CA    *CA
	// UpstreamRoots verify the real hosts behind intercepted TLS; nil
	// means this machine's roots (SSL_CERT_FILE is honoured).
	UpstreamRoots *x509.CertPool
	// Limits bound what the agent holds open here (relay.go).
	Limits Limits

	mu    sync.Mutex
	flows map[*flow]bool // open tunnels, intercepted connections and forwarded requests
	// forbid vets the address a connection is about to use (guard.go).
	forbid func(netip.Addr) string
}

// admit registers a connection the agent opens through the proxy,
// until done is called. Past Limits.MaxFlows it is refused: it answers
// 503, logs the refusal and returns a nil flow.
func (p *Proxy) admit(w http.ResponseWriter, host, target string) (f *flow, done func()) {
	p.mu.Lock()
	if p.flows == nil {
		p.flows = map[*flow]bool{}
	}
	if n := p.Limits.MaxFlows; n > 0 && len(p.flows) >= n {
		p.mu.Unlock()
		p.Log.Add(effects.Effect{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "too many open connections"})
		http.Error(w, "airbag: this session has "+strconv.Itoa(n)+" connections open through the proxy, the most it may; close some and retry", http.StatusServiceUnavailable)
		return nil, nil
	}
	f = newFlow(p.Limits.Idle, p.Limits.Drain)
	f.host, f.target = host, target
	p.flows[f] = true
	p.mu.Unlock()
	return f, func() {
		p.mu.Lock()
		delete(p.flows, f)
		p.mu.Unlock()
		f.stop()
	}
}

// Cut closes open connections to hosts outside keep. A tunnel opened
// before the session read a secret would otherwise carry it out:
// policy is checked when a connection opens, not on every byte.
func (p *Proxy) Cut(keep Allowlist, reason string) {
	p.mu.Lock()
	var cut []*flow
	for f := range p.flows {
		if !keep.Allows(f.host) {
			cut = append(cut, f)
			delete(p.flows, f)
		}
	}
	p.mu.Unlock()
	for _, f := range cut {
		if f.stop() { // not closed already as idle
			p.Log.Add(effects.Effect{Kind: "net.egress", Target: f.target, Verdict: "cut", Reason: reason})
		}
	}
}

func New(allow Allowlist, log *effects.Log) *Proxy {
	return &Proxy{Allow: allow, Log: log, forbid: forbidden, Limits: DefaultLimits(), Upstream: func(u *url.URL) (*url.URL, error) {
		return http.ProxyFromEnvironment(&http.Request{URL: u})
	}}
}

// canonHost spells a host one way, or says why it cannot be used. A
// name is lower case without its trailing dot; it must be ASCII (an IDN
// in its xn-- form: Go would turn a Unicode name into an xn-- host of
// its own after checks that lower-cased it to an allowed one) and have
// no empty label ("api.example.." would lose a dot in each later
// check). An IPv6 literal is written as netip writes it, its zone kept
// as given: interface names are case-sensitive.
func canonHost(h string) (string, string) {
	switch {
	case h == "":
		return "", ""
	case !isASCII(h):
		return "", "host names must be ASCII; write an international name in its xn-- form"
	case strings.Contains(h, ":"):
		a, err := netip.ParseAddr(h)
		if err != nil {
			return "", "not an IP address"
		}
		return a.String(), ""
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || strings.Contains(h, "..") {
		return "", "host name has an empty label"
	}
	return h, ""
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func (p *Proxy) Serve(l net.Listener) error {
	// A request's header must arrive within 30 s, and a connection
	// waiting for its next request is closed after Limits.KeepAlive.
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: p.Limits.KeepAlive}
	return srv.Serve(l)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	if r.Method == http.MethodConnect {
		host, _, _ = net.SplitHostPort(r.Host)
	}
	// From here on the host and port have one spelling, for the
	// allowlist, the rules, the log and the dial: a rule on
	// api.github.com:443 must see "API.GITHUB.COM.:0443" as that.
	canon, why := canonHost(host)
	port := r.URL.Port()
	if r.Method == http.MethodConnect {
		var err error
		// "api.example:" would read as 443 to the credential lookup
		// and as no port to the rules.
		if _, port, err = net.SplitHostPort(r.Host); (err != nil || port == "") && why == "" {
			why = "CONNECT names no port"
		}
	}
	if why == "" && canon == "" {
		why = "no host named" // the checks below would see "" and the dial something else
	}
	if why == "" && port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			why = "port " + clipTarget(port) + " is not a port number"
		} else {
			port = strconv.Itoa(n)
		}
	}
	if why != "" {
		p.Log.Add(effects.Effect{Kind: "net.egress", Target: clipTarget(r.Host), Verdict: "deny", Reason: why})
		http.Error(w, "airbag: "+clipTarget(r.Host)+": "+why, http.StatusBadRequest)
		return
	}
	host = canon
	switch {
	case port != "":
		r.Host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		r.Host = "[" + host + "]"
	case host != "":
		r.Host = host
	}
	if r.Method != http.MethodConnect && r.URL.Host != "" {
		r.URL.Host = r.Host // a proxy request's Host is its URL's
	}
	target := r.Host
	if p.Mirror != nil && host == "airbag.mirror" && r.Method != http.MethodConnect {
		p.Mirror.ServeHTTP(w, r)
		return
	}
	if !p.Allow.Allows(host) && (p.Gate == nil || !p.Gate.AllowsHost(host)) {
		if Registries.Allows(host) {
			p.Log.Add(effects.Effect{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "registry: use the mirror"})
			http.Error(w, "airbag: "+host+" is reached through http://airbag.mirror; point the package manager at the mirror (airbag sets GOPROXY, npm_config_registry, PIP_INDEX_URL)", http.StatusForbidden)
			return
		}
		p.Log.Add(effects.Effect{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "host not in allowlist"})
		http.Error(w, "airbag: egress to "+host+" denied by policy (host not in allowlist)", http.StatusForbidden)
		return
	}
	if port == "" && r.Method != http.MethodConnect {
		port = "80"
	}
	if !slices.Contains(webPorts, port) && !p.Allow.AllowsPort(host, port) {
		p.Log.Add(effects.Effect{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "port not allowed"})
		http.Error(w, "airbag: port "+port+" on "+host+" denied by policy (only 80 and 443 unless the allowlist names the port: --allow "+host+":"+port+")", http.StatusForbidden)
		return
	}
	if p.Gate != nil && p.Gate.Tainted() != "" && !Allowlist(DefaultAllow).Allows(host) {
		p.Log.Add(effects.Effect{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "secret-taint"})
		http.Error(w, "airbag: blocked by policy \"secret-taint\": this session read "+p.Gate.Tainted()+
			"; only model APIs and cached packages stay reachable", http.StatusForbidden)
		return
	}
	if p.Gate != nil {
		if d, id := p.Gate.Check(policy.Input{Effect: models.Effect{Kind: "net.connect", Target: host, Detail: port}}); d.Verdict != policy.Allow {
			p.Log.Add(effects.Effect{Kind: "net.egress", Target: target, Verdict: d.Verdict, Reason: d.Rule})
			http.Error(w, policy.Explain(d, id), http.StatusForbidden)
			return
		}
	}
	f, done := p.admit(w, host, target)
	if f == nil {
		return
	}
	defer done()
	p.Log.Add(effects.Effect{Kind: "net.egress", Target: target, Verdict: "allow"})
	// Talking to a host that is neither a model API nor a registry
	// brings outside data into the session: label it untrusted, so a
	// rule can keep that data from driving an irreversible effect.
	if p.Gate != nil && !Allowlist(DefaultAllow).Allows(host) && !Registries.Allows(host) {
		if p.Gate.Mark(taint.Untrusted, host) {
			p.Log.Add(effects.Effect{Kind: "label", Target: host, Verdict: "untrusted"})
		}
	}
	if r.Method == http.MethodConnect {
		if live := p.Creds.For(r.Host); live != nil && p.CA != nil {
			p.intercept(w, r, host, live, f)
			return
		}
		p.connect(w, r, host, f)
		return
	}
	p.forward(w, r, host, f)
}

// refuse answers a connection the address guard stopped.
func (p *Proxy) refuse(w http.ResponseWriter, target, host string, err error) bool {
	var b *blockedAddr
	if !errors.As(err, &b) {
		return false
	}
	p.Log.Add(effects.Effect{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "address: " + b.why})
	http.Error(w, "airbag: "+host+" "+b.Error(), http.StatusForbidden)
	return true
}

// connect opens a tunnel. It is registered (f) before the dial, so a
// cut while it dials closes it too.
func (p *Proxy) connect(w http.ResponseWriter, r *http.Request, host string, f *flow) {
	up, err := p.dial(r.Context(), f, r.Host, !p.Allow.explicitIP(host))
	if errors.Is(err, errStopped) {
		http.Error(w, "airbag: the connection to "+host+" was cut", http.StatusForbidden)
		return
	}
	if err != nil {
		if !p.refuse(w, r.Host, host, err) {
			http.Error(w, "airbag: "+err.Error(), http.StatusBadGateway) //nolint:gocritic // the return follows the if
		}
		return
	}
	if !f.hold(up) {
		http.Error(w, "airbag: the connection to "+host+" was cut", http.StatusForbidden)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	f.pipe(conn, buf.Reader, up)
}

// dial opens a TCP stream to hostport, through the host's upstream
// proxy when the host environment has one. The upstream proxy is the
// user's own and is not checked; it resolves the target itself. The
// stream belongs to f from the moment it connects: an upstream proxy
// that never answers CONNECT is closed with the flow (idle or cut).
func (p *Proxy) dial(ctx context.Context, f *flow, hostport string, check bool) (net.Conn, error) {
	pu, err := p.Upstream(&url.URL{Scheme: "https", Host: hostport})
	if err != nil {
		return nil, err
	}
	if pu == nil {
		return f.dialer(p.dialContext(check))(ctx, "tcp", hostport)
	}
	c, err := f.dialer((&net.Dialer{Timeout: 15 * time.Second}).DialContext)(ctx, "tcp", pu.Host)
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
	resp, err := http.ReadResponse(br, req) //nolint:bodyclose // the reply to CONNECT: its body is the tunnel, c, which is returned or closed below
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

// forward sends a plain HTTP request on. The upstream connection is
// the flow's: a cut or a quiet upstream (Limits.Idle) closes it and
// ends the request.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, host string, f *flow) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if !f.hold(&closer{cancel}) {
		http.Error(w, "airbag: the connection to "+host+" was cut", http.StatusForbidden)
		return
	}
	out := r.Clone(ctx)
	out.RequestURI = ""
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"} {
		out.Header.Del(h)
	}
	pu, err := p.Upstream(out.URL)
	if err != nil {
		http.Error(w, "airbag: "+err.Error(), http.StatusBadGateway)
		return
	}
	tr := &http.Transport{DialContext: f.dialer(p.dialContext(!p.Allow.explicitIP(host)))}
	if pu != nil {
		tr = &http.Transport{Proxy: http.ProxyURL(pu), DialContext: f.dialer((&net.Dialer{Timeout: 15 * time.Second}).DialContext)}
	}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(out)
	if err != nil {
		if !p.refuse(w, r.Host, host, err) {
			http.Error(w, "airbag: "+err.Error(), http.StatusBadGateway) //nolint:gocritic // the return follows the if
		}
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	// A client that stops reading blocks the copy in a write to it,
	// which closing the upstream does not end: stopping the flow ends
	// it with a write deadline in the past. Only while the body is
	// copied: the response is still flushed after this returns.
	stall := &closer{func() { _ = http.NewResponseController(w).SetWriteDeadline(time.Now()) }}
	if !f.hold(stall) {
		panic(http.ErrAbortHandler)
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		// The body broke off (the upstream failed, or was closed as
		// idle or cut), or the client stopped reading: the client must
		// see a broken response, not a complete one, which a chunked
		// body would otherwise end as.
		panic(http.ErrAbortHandler)
	}
	f.release(stall)
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
