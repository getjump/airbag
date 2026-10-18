package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/proxy/simulate"
)

// trap stands for the real hosts: it is the proxy's upstream, so every
// connection the proxy opens to any host arrives here, and it records
// what each asked for. A simulated host must never show up in it.
type trap struct {
	addr  string
	mu    sync.Mutex
	asked []string
}

func newTrap(t *testing.T) *trap {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &trap{addr: l.Addr().String()}
	var wg sync.WaitGroup
	t.Cleanup(func() { l.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				line, _ := bufio.NewReader(c).ReadString('\n')
				tr.mu.Lock()
				tr.asked = append(tr.asked, strings.TrimSpace(line))
				tr.mu.Unlock()
			})
		}
	})
	return tr
}

func (tr *trap) lines() []string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]string(nil), tr.asked...)
}

// never fails the test if anything asked the trap for host.
func (tr *trap) never(t *testing.T, host string) {
	t.Helper()
	for _, l := range tr.lines() {
		if strings.Contains(strings.ToLower(l), host) {
			t.Fatalf("the simulated host %s was contacted: %q", host, l)
		}
	}
}

var payStubs = []simulate.Stub{
	{Name: "charge", Match: simulate.Match{Method: "POST", Host: "api.pay.test", Path: "/v1/charges"},
		Respond: simulate.Respond{Status: 201, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"id":"ch_sim","status":"succeeded"}`}},
	{Name: "charge-get", Match: simulate.Match{Method: "GET", Host: "api.pay.test", Path: "/v1/charges/*"},
		Respond: simulate.Respond{Body: "one charge"}},
	{Name: "down", Match: simulate.Match{Host: "status.pay.test"}, Respond: simulate.Respond{Status: 503, Body: "maintenance"}},
}

// simProxy serves a proxy with stubs, an allowlist naming the
// simulated host (so that only simulation keeps it from being dialed)
// and control.test (a host that is dialed), and trap as every host.
func simProxy(t *testing.T, stubs []simulate.Stub, adjust func(*Proxy)) (*Proxy, *http.Client, string, *trap, string) {
	t.Helper()
	log, path := newLog(t)
	tr := newTrap(t)
	p := New(Allowlist{"api.pay.test", "status.pay.test", "control.test"}, log)
	p.Upstream = func(*url.URL) (*url.URL, error) { return &url.URL{Scheme: "http", Host: tr.addr}, nil }
	set, err := simulate.Compile(stubs)
	if err != nil {
		t.Fatal(err)
	}
	p.Simulation = set
	if p.CA, err = NewCA(set.Hosts()); err != nil {
		t.Fatal(err)
	}
	if adjust != nil {
		adjust(p)
	}
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() { _ = p.Serve(l) }()
	roots := x509.NewCertPool()
	if p.CA != nil {
		roots.AppendCertsFromPEM(p.CA.PEM)
	}
	pu := &url.URL{Scheme: "http", Host: l.Addr().String()}
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: roots}}}
	t.Cleanup(c.CloseIdleConnections)
	return p, c, path, tr, l.Addr().String()
}

func do(t *testing.T, c *http.Client, method, u, body string) (int, string, http.Header) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, u, r)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b), resp.Header
}

// A stub answers in place of its host, over HTTPS and plain HTTP, and a
// request no stub matches is refused: in neither case does the proxy
// open a connection to the host, although the allowlist names it. A
// host that is not simulated is dialed, through the same proxy, so the
// trap would have seen a dial.
func TestSimulatedHostIsNeverContacted(t *testing.T) {
	_, c, _, tr, addr := simProxy(t, payStubs, nil)
	if code, body, h := do(t, c, "POST", "https://api.pay.test/v1/charges", "amount=100"); code != 201 || body != `{"id":"ch_sim","status":"succeeded"}` || h.Get("Content-Type") != "application/json" {
		t.Fatalf("HTTPS stub: %d %q %v", code, body, h)
	}
	if code, body, _ := do(t, c, "GET", "https://api.pay.test/v1/charges/ch_1", ""); code != 200 || body != "one charge" {
		t.Fatalf("HTTPS glob stub: %d %q", code, body)
	}
	if code, body, _ := do(t, c, "GET", "http://status.pay.test/health", ""); code != 503 || body != "maintenance" {
		t.Fatalf("plain HTTP stub: %d %q", code, body)
	}
	if code, body, _ := do(t, c, "GET", "https://api.pay.test/v1/refunds", ""); code != 403 || !strings.Contains(body, "no stub matches") || !strings.Contains(body, "not sent") {
		t.Fatalf("unmatched request: %d %q", code, body)
	}
	if code, _, _ := do(t, c, "GET", "http://api.pay.test/v1/refunds", ""); code != 403 {
		t.Fatalf("unmatched plain request: %d", code)
	}
	// Another spelling of the name is the same simulated host.
	conn, _, code := connectVia(t, addr, "API.Pay.TEST.:443")
	conn.Close()
	if code != 200 {
		t.Fatalf("CONNECT in another spelling: %d", code)
	}
	tr.never(t, "pay.test")
	// The control: a host the stubs do not name goes to the trap.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://control.test/", nil)
	if resp, err := c.Do(req); err == nil {
		resp.Body.Close()
	}
	if got := tr.lines(); len(got) != 1 || !strings.HasPrefix(got[0], "CONNECT control.test:443") {
		t.Fatalf("the trap saw %q, want the control's CONNECT", got)
	}
}

// A stub needs no allowlist entry: its host is not reached.
func TestSimulatedHostNeedsNoAllow(t *testing.T) {
	_, c, _, tr, _ := simProxy(t, payStubs, func(p *Proxy) { p.Allow = nil })
	if code, body, _ := do(t, c, "GET", "https://api.pay.test/v1/charges/x", ""); code != 200 || body != "one charge" {
		t.Fatalf("%d %q", code, body)
	}
	tr.never(t, "pay.test")
}

// Each request is a row in the effect log: the stub that answered, or
// a refusal. The CONNECT itself is no egress, and the stubbed answer is
// not outside input, so no untrusted label.
func TestSimulatedIsLogged(t *testing.T) {
	_, c, path, _, _ := simProxy(t, payStubs, func(p *Proxy) {
		pol, err := policy.Load(t.TempDir(), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		p.Gate = policy.NewGate(pol, t.TempDir())
	})
	do(t, c, "POST", "https://api.pay.test/v1/charges", `{"card":"4242424242424242"}`)
	do(t, c, "GET", "https://api.pay.test/v1/refunds?secret=1", "")
	do(t, c, "GET", "http://status.pay.test/health", "")
	effs, err := effects.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range effs {
		if e.Kind == "net.egress" || e.Kind == "label" {
			t.Fatalf("a simulated host logged %+v", e)
		}
		if strings.Contains(e.Target+e.Reason, "4242") || strings.Contains(e.Target, "secret=1") {
			t.Fatalf("a body or query reached the log: %+v", e)
		}
		got = append(got, e.Kind+" "+e.Verdict+" "+e.Target+" "+e.Reason)
	}
	want := []string{
		"net.simulated allow POST api.pay.test/v1/charges charge",
		"net.simulated deny GET api.pay.test/v1/refunds no stub matches",
		"net.simulated allow GET status.pay.test/health down",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("log:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// The session CA vouches for the simulated names and for no other; a
// client that does not trust it fails the handshake, and that is
// logged, so review shows a tool that pins certificates.
func TestSimulatedTLSIsTheSessionCA(t *testing.T) {
	p, _, path, tr, addr := simProxy(t, payStubs, nil)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(p.CA.PEM)
	conn, br, code := connectVia(t, addr, "api.pay.test:443")
	if code != 200 || br.Buffered() != 0 {
		t.Fatalf("CONNECT %d", code)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: "api.pay.test", RootCAs: roots})
	if err := tc.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	leaf := tc.ConnectionState().PeerCertificates[0]
	_ = tc.Close()
	if err := leaf.VerifyHostname("api.pay.test"); err != nil {
		t.Fatal(err)
	}
	other, err := p.CA.leaf("other.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(other.Certificate[0])
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "other.test", Roots: roots}); err == nil {
		t.Fatal("the session CA vouches for a name no stub has")
	}
	// A client with its own roots (a pinned certificate) refuses it.
	conn, _, _ = connectVia(t, addr, "api.pay.test:443")
	tc = tls.Client(conn, &tls.Config{ServerName: "api.pay.test", RootCAs: x509.NewCertPool()})
	if err := tc.HandshakeContext(t.Context()); err == nil {
		t.Fatal("a client that does not trust the session CA completed the handshake")
	}
	_ = tc.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		effs, _ := effects.Read(path)
		found := false
		for _, e := range effs {
			found = found || (e.Kind == simulate.Kind && e.Verdict == "deny" && e.Target == "api.pay.test:443" && strings.Contains(e.Reason, "TLS to airbag's proxy failed"))
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the failed handshake was not logged: %+v", effs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	tr.never(t, "pay.test")
}

// Without a CA the TLS of a simulated host cannot be answered; it is
// refused, not passed to the host.
func TestSimulatedWithoutCARefuses(t *testing.T) {
	_, _, path, tr, addr := simProxy(t, payStubs, func(p *Proxy) { p.CA = nil })
	conn, _, code := connectVia(t, addr, "api.pay.test:443")
	conn.Close()
	if code != http.StatusServiceUnavailable {
		t.Fatalf("CONNECT %d, want 503", code)
	}
	effs, _ := effects.Read(path)
	if len(effs) != 1 || effs[0].Kind != simulate.Kind || effs[0].Verdict != "deny" {
		t.Fatalf("log %+v", effs)
	}
	tr.never(t, "pay.test")
}

// After a secret read the session reaches only model APIs; a stub
// still answers, since nothing leaves, and Cut leaves its open
// connection alone, so a run is the same whatever it reads.
func TestSimulatedAfterSecretRead(t *testing.T) {
	var gate *policy.Gate
	p, c, _, tr, addr := simProxy(t, payStubs, func(p *Proxy) {
		pol, err := policy.Load(t.TempDir(), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		gate = policy.NewGate(pol, t.TempDir())
		p.Gate = gate
	})
	var reused []bool
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = append(reused, i.Reused) }}
	get := func() {
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), http.MethodGet, "https://api.pay.test/v1/charges/x", nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(b) != "one charge" {
			t.Fatalf("%d %q", resp.StatusCode, b)
		}
	}
	get()
	gate.Taint(".env")
	p.Cut(DefaultAllow, "secret-taint")
	get()
	if len(reused) != 2 || !reused[1] {
		t.Fatalf("the simulated connection was cut: reused %v", reused)
	}
	if conn, _, code := connectVia(t, addr, "control.test:443"); code != 403 {
		conn.Close()
		t.Fatalf("a host that is not simulated, after the read: %d", code)
	} else {
		conn.Close()
	}
	tr.never(t, "pay.test")
}

// A delay holds the answer back, and the proxy closing ends it rather
// than leaving the request waiting (goleak checks the rest).
func TestSimulatedDelay(t *testing.T) {
	stubs := []simulate.Stub{
		{Name: "slow", Match: simulate.Match{Host: "slow.pay.test", Path: "/slow"}, Respond: simulate.Respond{Body: "late", Delay: "300ms"}},
		{Name: "hang", Match: simulate.Match{Host: "slow.pay.test", Path: "/hang"}, Respond: simulate.Respond{Delay: "10m"}},
	}
	p, c, path, _, _ := simProxy(t, stubs, nil)
	start := time.Now()
	if code, body, _ := do(t, c, "GET", "https://slow.pay.test/slow", ""); code != 200 || body != "late" || time.Since(start) < 300*time.Millisecond {
		t.Fatalf("%d %q after %s", code, body, time.Since(start))
	}
	done := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://slow.pay.test/hang", nil)
		resp, err := c.Do(req)
		if err == nil {
			resp.Body.Close()
			err = errors.New(resp.Status)
		}
		done <- err
	}()
	for deadline := time.Now().Add(5 * time.Second); ; {
		effs, _ := effects.Read(path)
		if len(effs) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the hanging request was not answered by its stub")
		}
		time.Sleep(10 * time.Millisecond)
	}
	p.Close()
	select {
	case err := <-done:
		if err == nil || strings.Contains(err.Error(), "200") {
			t.Fatalf("a request cut in its delay got an answer: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("closing the proxy did not end a request waiting in its delay")
	}
}

// The answer is the stub's as written: no Content-Type guessed, a
// Content-Length of its own, no body to HEAD. A request body past
// MaxRequestBody is not read: the answer comes, and the connection
// closes after it.
func TestSimulatedAnswerAsWritten(t *testing.T) {
	stubs := []simulate.Stub{{Name: "raw", Match: simulate.Match{Host: "api.pay.test"}, Respond: simulate.Respond{Body: "<html>not sniffed</html>", Headers: map[string]string{"X-Stub": "yes"}}}}
	_, c, _, _, _ := simProxy(t, stubs, nil)
	code, body, h := do(t, c, "GET", "https://api.pay.test/", "")
	if code != 200 || body != "<html>not sniffed</html>" || h.Get("Content-Type") != "" || h.Get("X-Stub") != "yes" || h.Get("Content-Length") != "24" {
		t.Fatalf("%d %q %v", code, body, h)
	}
	if code, body, _ := do(t, c, "HEAD", "https://api.pay.test/", ""); code != 200 || body != "" {
		t.Fatalf("HEAD %d %q", code, body)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.pay.test/", strings.NewReader(strings.Repeat("x", simulate.MaxRequestBody+10)))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(b) != "<html>not sniffed</html>" || !resp.Close {
		t.Fatalf("large body: %d %q close=%v", resp.StatusCode, b, resp.Close)
	}
}

// On a simulated connection a request naming another host is refused:
// the connection's stubs are for its own host.
func TestSimulatedOtherHostHeader(t *testing.T) {
	p, _, _, tr, addr := simProxy(t, payStubs, nil)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(p.CA.PEM)
	conn, _, _ := connectVia(t, addr, "api.pay.test:443")
	tc := tls.Client(conn, &tls.Config{ServerName: "api.pay.test", RootCAs: roots})
	defer func() { _ = tc.Close() }()
	_, _ = io.WriteString(tc, "GET /v1/charges/x HTTP/1.1\r\nHost: control.test\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("%d", resp.StatusCode)
	}
	tr.never(t, "control.test")
	tr.never(t, "pay.test")
}

// The log holds a request's path as sent, percent-encoded: decoded, a
// %0a or %1b would put a line break or an escape sequence the agent
// chose in the log, and on the terminal of whoever reads it.
func TestSimulatedLogsThePathAsSent(t *testing.T) {
	stubs := []simulate.Stub{{Name: "any", Match: simulate.Match{Host: "api.pay.test", Path: "/v1/**"}, Respond: simulate.Respond{Body: "ok"}}}
	_, c, path, _, _ := simProxy(t, stubs, nil)
	if code, body, _ := do(t, c, http.MethodGet, "https://api.pay.test/v1/a%1b%5B2K%0d%0aSimulated", ""); code != 200 || body != "ok" {
		t.Fatalf("%d %q", code, body)
	}
	if code, _, _ := do(t, c, http.MethodGet, "https://api.pay.test/v2/%1b%0a", ""); code != 403 {
		t.Fatalf("%d", code)
	}
	effs, _ := effects.Read(path)
	if len(effs) != 2 {
		t.Fatalf("%+v", effs)
	}
	for _, e := range effs {
		if strings.ContainsFunc(e.Target+e.Reason, func(r rune) bool { return r < ' ' || r == 0x7f }) {
			t.Fatalf("a control character in the log: %q", e.Target+" "+e.Reason)
		}
	}
	if effs[0].Target != "GET api.pay.test/v1/a%1b%5B2K%0d%0aSimulated" || effs[1].Target != "GET api.pay.test/v2/%1b%0a" {
		t.Fatalf("targets %q, %q", effs[0].Target, effs[1].Target)
	}
}
