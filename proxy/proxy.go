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
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/getjump/airbag/audit"
	"github.com/getjump/airbag/creds"
	"github.com/getjump/airbag/internal/netcap"
	"github.com/getjump/airbag/policy"
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

// Gate owns policy, approvals and labels independently of the proxy.
// Tainted must say something (a reason) whenever the labels are not
// known to be clean, as when they could not be read: "" opens egress
// past the core hosts.
type Gate interface {
	Check(policy.Input) (policy.Decision, string)
	AllowsHost(string) bool
	Tainted() string
	MarkUntrusted(string) bool
}

// A Proxy made as a struct literal, without New, is bounded as one New
// makes: the address guard, and each Limits field left zero, are New's
// (guard, limits); a nil Upstream is no upstream proxy. A nil Log, or a
// Gate holding a nil pointer, is refused with 503 rather than run with
// no record or no policy.
type Proxy struct {
	Allow Allowlist
	Log   audit.Recorder
	// Gate applies policy rules on top of the allowlist (optional): with
	// none, the allowlist alone decides.
	Gate Gate
	// Mirror serves http://airbag.mirror/ (optional).
	Mirror http.Handler
	// Upstream returns the host's own proxy for a target, if any, so
	// airbag works behind a corporate or sandbox proxy. nil is none.
	Upstream func(*url.URL) (*url.URL, error)
	// Creds are the credentials bound to hosts; with CA set, TLS to
	// those hosts is terminated here (mitm.go).
	Creds creds.Set
	CA    *CA
	// UpstreamRoots verify the real hosts behind intercepted TLS; nil
	// means this machine's roots (SSL_CERT_FILE is honoured).
	UpstreamRoots *x509.CertPool
	// Limits bound what the agent holds open here (relay.go); a field
	// left zero is New's.
	Limits Limits

	closed bool
	mu     sync.Mutex
	flows  map[*flow]bool // open tunnels, intercepted connections and forwarded requests
	// forbid vets the address a connection is about to use (guard.go);
	// nil is forbidden.
	forbid func(netip.Addr) string
	// admitting runs as admit starts, when set: a test acts there, after
	// a connection's checks and before it is registered.
	admitting func()
	// now is the clock flows measure quiet by, when set: a test's, which
	// moves when the test sees bytes arrive, not as a busy runner pauses.
	now func() time.Time
}

// admit registers a connection the agent opens through the proxy,
// until done is called. Past Limits.MaxFlows it is refused: it answers
// 503, logs the refusal and returns a nil flow.
func (p *Proxy) admit(w http.ResponseWriter, host, target string) (f *flow, done func()) {
	if p.admitting != nil {
		p.admitting()
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		answer(w, "airbag: proxy stopped", http.StatusServiceUnavailable)
		return nil, nil
	}
	if p.flows == nil {
		p.flows = map[*flow]bool{}
	}
	lim := p.limits()
	if n := lim.MaxFlows; n > 0 && len(p.flows) >= n {
		p.mu.Unlock()
		p.Log.Add(audit.Event{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "too many open connections"})
		answer(w, "airbag: this session has "+strconv.Itoa(n)+" connections open through the proxy, the most it may; close some and retry", http.StatusServiceUnavailable)
		return nil, nil
	}
	f = newFlow(lim.Idle, lim.Drain, p.now)
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

// Close cancels tracked flows and refuses late admission. The owner must also
// close its HTTP server/listener to stop accepting connections.
func (p *Proxy) Close() {
	p.mu.Lock()
	p.closed = true
	flows := p.flows
	p.flows = nil
	p.mu.Unlock()
	for f := range flows {
		f.stop()
	}
}

func (p *Proxy) recordAll(events []audit.Event) {
	if isNil(p.Log) {
		return // ServeHTTP admits nothing without a log
	}
	if bulk, ok := p.Log.(interface{ AddAll([]audit.Event) error }); ok {
		_ = bulk.AddAll(events)
		return
	}
	for _, event := range events {
		p.Log.Add(event)
	}
}

// Cut closes open connections to hosts outside keep. A tunnel opened
// before the session read a secret would otherwise carry it out:
// policy is checked when a connection opens, not on every byte. The
// read waits for Cut, so every connection is closed first and the log,
// which other writers may hold up, is written after.
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
	var logged []audit.Event
	for _, f := range cut {
		if f.stop() { // not closed already as idle
			logged = append(logged, audit.Event{Kind: "net.egress", Target: f.target, Verdict: "cut", Reason: reason})
		}
	}
	p.recordAll(logged)
}

// gate returns the Gate that decides, nil for none; ok is false for a
// Gate holding a nil pointer, which could answer no check.
func (p *Proxy) gate() (g Gate, ok bool) {
	if isNil(p.Gate) {
		return nil, p.Gate == nil
	}
	return p.Gate, true
}

// isNil reports whether v is nil, or an interface holding a nil pointer
// (or map, func, chan, slice).
func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Chan, reflect.Slice, reflect.Interface, reflect.UnsafePointer:
		return rv.IsNil()
	}
	return false
}

// upstream is Upstream, or no upstream proxy when it is nil.
func (p *Proxy) upstream(u *url.URL) (*url.URL, error) {
	if p.Upstream == nil {
		return nil, nil
	}
	return p.Upstream(u)
}

func New(allow Allowlist, log audit.Recorder) *Proxy {
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

func (p *Proxy) HTTPServer() *http.Server {
	// A request's header must arrive within 30 s, and a connection
	// waiting for its next request is closed after Limits.KeepAlive.
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: p.limits().KeepAlive}
	return srv
}

// AnswerWrite bounds the write of an answer the proxy gives itself (a
// refusal, an error), which has no flow to close it: a client that
// sends requests and reads none of the answers would otherwise hold the
// connection in a blocked write.
const AnswerWrite = 30 * time.Second

// answer is http.Error within AnswerWrite, as the connection's last
// answer. net/http reads what is left of the request's body, up to
// 256 KiB, with no deadline of its own: before it writes an answer on
// a connection it keeps, and after the answer in any case. A client
// that declares a body and sends none would hold the connection there.
// On a connection it closes after the answer it skips the first read;
// the second gets AnswerWrite too.
func answer(w http.ResponseWriter, msg string, code int) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(AnswerWrite))
	_ = rc.SetReadDeadline(time.Now().Add(AnswerWrite))
	w.Header().Set("Connection", "close")
	http.Error(w, msg, code)
}

// pacedChunk is how much of a paced answer must go out within
// AnswerWrite.
const pacedChunk = 64 << 10

// paced writes the mirror's answers, which have no flow to close them
// either and may be whole packages: each pacedChunk bytes must go out
// within AnswerWrite. A client that asks for a package and reads none
// of it would otherwise hold the connection in a blocked write. A
// chunk goes out once the socket has room, which it gets back only
// after the client has read most of what it holds (on Linux, about
// 200 KiB): a client that reads slower than a few KiB a second is cut
// off too. What net/http writes after the handler returns goes out
// under the deadline serveMirror renews then, which the next request
// on the connection clears (ServeHTTP).
//
// It has only Header, WriteHeader, Write and Unwrap on purpose: a
// ReadFrom or WriteString passed through would write without renewing.
type paced struct {
	http.ResponseWriter
	rc *http.ResponseController
}

func (w paced) renew() { _ = w.rc.SetWriteDeadline(time.Now().Add(AnswerWrite)) }

func (w paced) WriteHeader(code int) {
	w.renew()
	w.ResponseWriter.WriteHeader(code)
}

func (w paced) Write(b []byte) (int, error) {
	if len(b) == 0 { // still sends the header
		w.renew()
		return w.ResponseWriter.Write(b)
	}
	n := 0
	for len(b) > 0 {
		c := min(len(b), pacedChunk)
		w.renew()
		m, err := w.ResponseWriter.Write(b[:c])
		n += m
		if err != nil {
			return n, err
		}
		b = b[c:]
	}
	return n, nil
}

// Unwrap lets a ResponseController reach the connection.
func (w paced) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// serveMirror has the mirror answer r through paced. The mirror may
// take longer than AnswerWrite after its last write (an upstream body
// slow to end), so what net/http still holds when it returns gets a
// fresh deadline.
func (p *Proxy) serveMirror(w http.ResponseWriter, r *http.Request) {
	pw := paced{w, http.NewResponseController(w)}
	body := r.ContentLength != 0
	if body {
		// The mirror reads no body; one left unsent would hold the
		// connection, as in answer.
		w.Header().Set("Connection", "close")
	}
	p.Mirror.ServeHTTP(pw, r)
	pw.renew()
	if body {
		_ = pw.rc.SetReadDeadline(time.Now().Add(AnswerWrite))
	}
}

// LimitListener applies the configured host connection cap.
func (p *Proxy) LimitListener(l net.Listener) net.Listener {
	if n := p.limits().MaxFlows; n > 0 {
		return netcap.Limit(l, 2*n)
	}
	return l
}
func (p *Proxy) Serve(l net.Listener) error { return p.HTTPServer().Serve(p.LimitListener(l)) }

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The previous response on this connection may have left a write
	// deadline (answer, forward); this request starts without one.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	// Read once: every check below sees this gate, or none.
	g, ok := p.gate()
	switch {
	case isNil(p.Log):
		answer(w, "airbag: proxy log not configured", http.StatusServiceUnavailable)
		return
	case !ok:
		p.Log.Add(audit.Event{Kind: "net.egress", Target: clipTarget(r.Host), Verdict: "deny", Reason: "proxy gate not configured"})
		answer(w, "airbag: proxy gate not configured", http.StatusServiceUnavailable)
		return
	}
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
		p.Log.Add(audit.Event{Kind: "net.egress", Target: clipTarget(r.Host), Verdict: "deny", Reason: why})
		answer(w, "airbag: "+clipTarget(r.Host)+": "+why, http.StatusBadRequest)
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
	if !isNil(p.Mirror) && host == "airbag.mirror" && r.Method != http.MethodConnect {
		p.serveMirror(w, r)
		return
	}
	if !p.Allow.Allows(host) && (g == nil || !g.AllowsHost(host)) {
		if Registries.Allows(host) {
			p.Log.Add(audit.Event{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "registry: use the mirror"})
			answer(w, "airbag: "+host+" is reached through http://airbag.mirror; point the package manager at the mirror (airbag sets GOPROXY, npm_config_registry, PIP_INDEX_URL)", http.StatusForbidden)
			return
		}
		p.Log.Add(audit.Event{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "host not in allowlist"})
		answer(w, "airbag: egress to "+host+" denied by policy (host not in allowlist)", http.StatusForbidden)
		return
	}
	if port == "" && r.Method != http.MethodConnect {
		port = "80"
	}
	if !slices.Contains(webPorts, port) && !p.Allow.AllowsPort(host, port) {
		p.Log.Add(audit.Event{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "port not allowed"})
		answer(w, "airbag: port "+port+" on "+host+" denied by policy (only 80 and 443 unless the allowlist names the port: --allow "+host+":"+port+")", http.StatusForbidden)
		return
	}
	if p.refuseTainted(w, g, host, target) {
		return
	}
	if g != nil {
		if d, id := g.Check(policy.Input{Effect: policy.Effect{Kind: "net.connect", Target: host, Detail: port}}); d.Verdict != policy.Allow {
			p.Log.Add(audit.Event{Kind: "net.egress", Target: target, Verdict: d.Verdict, Reason: d.Rule})
			answer(w, policy.Explain(d, id), http.StatusForbidden)
			return
		}
	}
	f, done := p.admit(w, host, target)
	if f == nil {
		return
	}
	defer done()
	// A secret read while this connection was checked: Cut has run
	// already and did not see it. The label is set before Cut takes
	// p.mu, and admit registered the flow under p.mu, so either Cut saw
	// the flow or this sees the label.
	if p.refuseTainted(w, g, host, target) {
		return
	}
	p.Log.Add(audit.Event{Kind: "net.egress", Target: target, Verdict: "allow"})
	// Talking to a host that is neither a model API nor a registry
	// brings outside data into the session: label it untrusted, so a
	// rule can keep that data from driving an irreversible effect.
	if g != nil && !Allowlist(DefaultAllow).Allows(host) && !Registries.Allows(host) {
		if g.MarkUntrusted(host) {
			p.Log.Add(audit.Event{Kind: "label", Target: host, Verdict: "untrusted"})
		}
	}
	if r.Method == http.MethodConnect {
		if live := p.Creds.For(r.Host); live != nil && p.CA != nil {
			p.intercept(w, r, g, host, live, f)
			return
		}
		p.connect(w, r, host, f)
		return
	}
	p.forward(w, r, host, f)
}

// refuseTainted refuses a connection to a host other than a model API
// once the session has read a secret.
func (p *Proxy) refuseTainted(w http.ResponseWriter, g Gate, host, target string) bool {
	if Allowlist(DefaultAllow).Allows(host) {
		return false
	}
	if read := tainted(g); read != "" {
		p.Log.Add(audit.Event{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "secret-taint"})
		answer(w, "airbag: blocked by policy \"secret-taint\": this session read "+read+
			"; only model APIs and cached packages stay reachable", http.StatusForbidden)
		return true
	}
	return false
}

// tainted is what g says the session read, "" with no gate.
func tainted(g Gate) string {
	if g == nil {
		return ""
	}
	return g.Tainted()
}

// refuse answers a connection the address guard stopped.
func (p *Proxy) refuse(w http.ResponseWriter, target, host string, err error) bool {
	var b *blockedAddr
	if !errors.As(err, &b) {
		return false
	}
	p.Log.Add(audit.Event{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "address: " + b.why})
	answer(w, "airbag: "+host+" "+b.Error(), http.StatusForbidden)
	return true
}

// connect opens a tunnel. It is registered (f) before the dial, so a
// cut while it dials closes it too.
func (p *Proxy) connect(w http.ResponseWriter, r *http.Request, host string, f *flow) {
	up, err := p.dial(r.Context(), f, r.Host, !p.Allow.explicitIP(host))
	if errors.Is(err, errStopped) {
		answer(w, "airbag: the connection to "+host+" was cut", http.StatusForbidden)
		return
	}
	if err != nil {
		if !p.refuse(w, r.Host, host, err) {
			answer(w, "airbag: "+err.Error(), http.StatusBadGateway)
		}
		return
	}
	if !f.hold(up) {
		answer(w, "airbag: the connection to "+host+" was cut", http.StatusForbidden)
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
// that never answers CONNECT is closed with the flow (idle or cut), and
// dial then says errStopped, as it does for a direct dial.
func (p *Proxy) dial(ctx context.Context, f *flow, hostport string, check bool) (net.Conn, error) {
	pu, err := p.upstream(&url.URL{Scheme: "https", Host: hostport})
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
	fail := func(err error) (net.Conn, error) {
		c.Close()
		if f.isStopped() {
			return nil, errStopped
		}
		return nil, err
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: hostport}, Host: hostport, Header: http.Header{}}
	if pu.User != nil {
		req.Header.Set("Proxy-Authorization", "Basic "+basicAuth(pu.User))
	}
	if err := req.Write(c); err != nil {
		return fail(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req) //nolint:bodyclose // the reply to CONNECT: its body is the tunnel, c, which is returned or closed below
	if err != nil {
		return fail(err)
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
		w.Header().Set("Connection", "close") // an answer to a stopped flow, as below
		answer(w, "airbag: the connection to "+host+" was cut", http.StatusForbidden)
		return
	}
	// A client that stops sending its request body blocks the transport
	// in a read of that body, and RoundTrip waits for it: neither the
	// cancel nor closing the upstream ends the read. Stopping the flow
	// ends it with a read deadline in the past, only while the handler
	// runs. That deadline also fails net/http's own read of the
	// connection, which cancels the context of the connection's next
	// requests, so once it has fired the connection serves no more: an
	// answer to a stopped flow says so (stopped, below), and one that
	// did not, the flow stopping later, is aborted.
	closing := false
	if r.Body != nil && r.Body != http.NoBody {
		body := &readStop{rc: http.NewResponseController(w), live: true}
		if !f.hold(body) {
			// The flow stopped first, and hold fired body already.
			w.Header().Set("Connection", "close")
			answer(w, "airbag: the connection to "+host+" was cut", http.StatusForbidden)
			return
		}
		defer func() {
			f.release(body)
			if body.end() && !closing {
				panic(http.ErrAbortHandler)
			}
		}()
	}
	// stopped marks an answer to a stopped flow as the connection's last.
	stopped := func() {
		if f.isStopped() {
			w.Header().Set("Connection", "close")
			closing = true
		}
	}
	out := r.Clone(ctx)
	out.RequestURI = ""
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"} {
		out.Header.Del(h)
	}
	pu, err := p.upstream(out.URL)
	if err != nil {
		stopped()
		answer(w, "airbag: "+err.Error(), http.StatusBadGateway)
		return
	}
	tr := &http.Transport{DialContext: f.dialer(p.dialContext(!p.Allow.explicitIP(host)))}
	if pu != nil {
		tr = &http.Transport{Proxy: http.ProxyURL(pu), DialContext: f.dialer((&net.Dialer{Timeout: 15 * time.Second}).DialContext)}
	}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(out)
	if err != nil {
		stopped()
		if !p.refuse(w, r.Host, host, err) {
			answer(w, "airbag: "+err.Error(), http.StatusBadGateway)
		}
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	// A client that stops reading blocks the copy in a write to it,
	// which closing the upstream does not end: stopping the flow ends
	// it with a write deadline in the past. That covers the copy and the
	// flush of what is buffered (headers too large for the socket, say);
	// the few bytes net/http writes after the handler returns (the end
	// of a chunked body) get a deadline of Limits.Idle, which the next
	// request on the connection clears (ServeHTTP).
	rc := http.NewResponseController(w)
	stall := &closer{func() { _ = rc.SetWriteDeadline(time.Now()) }}
	if !f.hold(stall) {
		panic(http.ErrAbortHandler)
	}
	stopped()
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err == nil {
		err = rc.Flush()
	}
	if err != nil {
		// The body broke off (the upstream failed, or was closed as
		// idle or cut), or the client stopped reading: the client must
		// see a broken response, not a complete one, which a chunked
		// body would otherwise end as.
		panic(http.ErrAbortHandler)
	}
	f.release(stall)
	if idle := p.limits().Idle; idle > 0 {
		_ = rc.SetWriteDeadline(time.Now().Add(idle))
	}
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
