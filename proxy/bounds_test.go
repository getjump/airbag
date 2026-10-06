package proxy

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getjump/airbag/audit"
	"github.com/getjump/airbag/internal/effects"
)

// The bounds on what the agent can hold open on the host side, each
// checked against its scenario from the stress measurements: after the
// client closes, or after a bound runs out, the proxy's goroutines and
// file descriptors are back where they started.

// testLimits are short enough for a test: the defaults are minutes.
var testLimits = Limits{Idle: 5 * time.Second, Drain: 200 * time.Millisecond, KeepAlive: 200 * time.Millisecond, MaxFlows: MaxFlows}

// usage is the test binary's goroutines and open file descriptors.
func usage() (goroutines, fds int) {
	es, _ := os.ReadDir("/dev/fd")
	return runtime.NumGoroutine(), len(es)
}

// settle waits up to d for goroutines and fds to come down to the
// baseline plus slack, then fails with what is left.
func settle(t *testing.T, g0, fd0, slackG, slackFD int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	g, fd := usage()
	for (g > g0+slackG || fd > fd0+slackFD) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		g, fd = usage()
	}
	if g > g0+slackG || fd > fd0+slackFD {
		var b bytes.Buffer
		_ = pprof.Lookup("goroutine").WriteTo(&b, 1)
		t.Fatalf("after %v: goroutines %d (baseline %d), fds %d (baseline %d)\n%s", d, g, g0, fd, fd0, b.String())
	}
}

// listenTCP serves each connection with handle until the test ends.
func listenTCP(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { l.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { handle(c) })
		}
	})
	return l.Addr().String()
}

// echoConn echoes c until its end, then closes it. It copies through a
// buffer: io.Copy between TCP connections splices through pipes that
// Go keeps for reuse, and their fds would count against the proxy.
func echoConn(c net.Conn) {
	_, _ = io.Copy(struct{ io.Writer }{c}, struct{ io.Reader }{c})
	c.Close()
}

// ignoresEOF is an upstream that reads until the client's end and then
// keeps its side open, silent. It counts the connections it holds.
type ignoresEOF struct {
	mu   sync.Mutex
	held []net.Conn
	eof  atomic.Int32
}

func (s *ignoresEOF) handle(c net.Conn) {
	s.mu.Lock()
	s.held = append(s.held, c)
	s.mu.Unlock()
	_, _ = io.Copy(io.Discard, c)
	s.eof.Add(1)
}

func (s *ignoresEOF) accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.held)
}

func (s *ignoresEOF) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.held {
		c.Close()
	}
}

func boundedProxy(t *testing.T, lim Limits) (*Proxy, string, string) {
	t.Helper()
	return boundedProxyVia(t, lim, "", nil)
}

// boundedProxyVia is boundedProxy behind the upstream proxy at
// upstream ("": none), with adjust (if any) run on the proxy before it
// serves.
func boundedProxyVia(t *testing.T, lim Limits, upstream string, adjust func(*Proxy)) (*Proxy, string, string) {
	t.Helper()
	log, path := newLog(t)
	p := New(Allowlist{"127.0.0.1:*"}, log)
	p.Upstream = func(*url.URL) (*url.URL, error) {
		if upstream == "" {
			return nil, nil
		}
		return &url.URL{Scheme: "http", Host: upstream}, nil
	}
	p.Limits = lim
	if adjust != nil {
		adjust(p)
	}
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() { _ = p.Serve(l) }()
	return p, l.Addr().String(), path
}

func connectVia(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	return c, br, resp.StatusCode
}

// An upstream that ignores the agent's end of a tunnel no longer keeps
// it: the proxy closes both sides once the upstream has been quiet for
// Drain. Before, each such tunnel kept 2 goroutines and 5 fds.
func TestTunnelUpstreamIgnoresEOF(t *testing.T) {
	const n = 50
	up := &ignoresEOF{}
	target := listenTCP(t, up.handle)
	t.Cleanup(up.close)
	_, pa, _ := boundedProxy(t, testLimits)
	g0, fd0 := usage()
	for range n {
		c, _, code := connectVia(t, pa, target)
		if code != http.StatusOK {
			t.Fatalf("CONNECT: %d", code)
		}
		_, _ = c.Write([]byte("data"))
		c.Close() // the agent is gone
	}
	// The upstream's own connections stay open (n fds): it ignores the
	// end. Everything on the proxy's side goes.
	settle(t, g0, fd0, 2, n+2, 3*time.Second)
	if got := up.eof.Load(); got != n {
		t.Fatalf("the upstream saw the end of %d tunnels, want %d", got, n)
	}
}

// A tunnel on which nothing moves for Idle is closed; one that keeps
// carrying data past Idle is not.
func TestTunnelIdle(t *testing.T) {
	target := listenTCP(t, echoConn)
	lim := testLimits
	lim.Idle = 300 * time.Millisecond
	_, pa, _ := boundedProxy(t, lim)
	g0, fd0 := usage()

	quiet, quietR, _ := connectVia(t, pa, target)
	defer quiet.Close()
	busy, busyR, _ := connectVia(t, pa, target)
	defer busy.Close()
	start := time.Now()
	for time.Since(start) < 3*lim.Idle {
		_, _ = busy.Write([]byte("ping\n"))
		_ = busy.SetReadDeadline(time.Now().Add(time.Second))
		if line, err := busyR.ReadString('\n'); err != nil || line != "ping\n" {
			t.Fatalf("the busy tunnel broke after %v: %q %v", time.Since(start), line, err)
		}
		time.Sleep(lim.Idle / 4)
	}
	_ = quiet.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := quietR.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("the quiet tunnel is still open after %v: %v", time.Since(start), err)
	}
	quiet.Close()
	busy.Close()
	settle(t, g0, fd0, 1, 1, 3*time.Second)
}

// When the agent finishes sending, the upstream is told (a half-close)
// and its answer still comes back.
func TestTunnelPassesHalfClose(t *testing.T) {
	target := listenTCP(t, func(c net.Conn) {
		defer c.Close()
		b, _ := io.ReadAll(c) // to the agent's end
		_, _ = c.Write(append([]byte("got "), b...))
	})
	_, pa, _ := boundedProxy(t, testLimits)
	c, br, _ := connectVia(t, pa, target)
	defer c.Close()
	_, _ = c.Write([]byte("request"))
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b, err := io.ReadAll(br); err != nil || string(b) != "got request" {
		t.Fatalf("answer after the half-close: %q %v", b, err)
	}
}

// When the upstream finishes sending first, the agent is told at once
// (not after Drain), while its own side stays open.
func TestTunnelPassesUpstreamHalfClose(t *testing.T) {
	target := listenTCP(t, func(c net.Conn) {
		defer c.Close()
		_, _ = c.Write([]byte("answer"))
		_ = c.(*net.TCPConn).CloseWrite()
		_, _ = io.Copy(io.Discard, c) // to the agent's end
	})
	lim := testLimits
	lim.Drain = time.Hour
	_, pa, _ := boundedProxy(t, lim)
	c, br, _ := connectVia(t, pa, target)
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b, err := io.ReadAll(br); err != nil || string(b) != "answer" {
		t.Fatalf("the upstream's end did not reach the agent: %q %v", b, err)
	}
}

// An intercepted connection the client keeps idle between requests is
// closed after KeepAlive. Before, each kept about 6 goroutines.
func TestInterceptIdleKeepAlive(t *testing.T) {
	const k = 20
	up, _ := echo(t)
	c0, live, _ := mitmProxyWith(t, up, "", func(p *Proxy) { p.Limits = testLimits })
	tr0 := c0.Transport.(*http.Transport)
	g0, fd0 := usage()
	var trs []*http.Transport
	for range k {
		tr := tr0.Clone()
		trs = append(trs, tr)
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, up.URL+"/x", nil)
		req.Header.Set("Authorization", "Bearer "+live.Placeholder)
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	// The clients keep their connections; the proxy closes them, and
	// the clients' pools then drop them too.
	settle(t, g0, fd0, 2, 2, 3*time.Second)
	for _, tr := range trs {
		tr.CloseIdleConnections()
	}
}

// An intercepted request on which nothing moves for Idle (a host that
// stalls) is closed; one whose response keeps coming past Idle is not.
// net/http does the copying there: the flow sees the bytes only through
// the connections it watches.
func TestInterceptIdle(t *testing.T) {
	// Long enough that a second TLS handshake through the proxy on a
	// busy runner does not count as a stall.
	const idle = time.Second
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := 12 // a byte each Idle/4: 3×Idle
		if r.URL.Path == "/quiet" {
			n = 1
		}
		rc := http.NewResponseController(w)
		for i := range n {
			if i > 0 {
				time.Sleep(idle / 4)
			}
			_, _ = io.WriteString(w, "x")
			_ = rc.Flush()
		}
		if r.URL.Path == "/quiet" {
			<-r.Context().Done() // until the proxy closes the connection
		}
	}))
	t.Cleanup(up.Close)
	c, _, _ := mitmProxyWith(t, up, "", func(p *Proxy) { p.Limits = testLimits; p.Limits.Idle = idle })
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second) // a failing run ends too
	defer cancel()
	get := func(path string) *http.Response {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, up.URL+path, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	quiet := get("/quiet")
	defer quiet.Body.Close()
	start := time.Now()
	busy := get("/busy")
	b, err := io.ReadAll(busy.Body)
	busy.Body.Close()
	if err != nil || string(b) != strings.Repeat("x", 12) {
		t.Fatalf("the busy intercepted connection broke after %v: %q %v", time.Since(start), b, err)
	}
	if b, err := io.ReadAll(quiet.Body); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the quiet intercepted connection is still open after %v: %q %v", time.Since(start), b, err)
	}
}

// A plain forwarded request's connection, idle between requests, is
// closed after KeepAlive.
func TestForwardIdleKeepAlive(t *testing.T) {
	const k = 20
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	t.Cleanup(srv.Close)
	_, pa, _ := boundedProxy(t, testLimits)
	pu, _ := url.Parse("http://" + pa)
	g0, fd0 := usage()
	var trs []*http.Transport
	for range k {
		tr := &http.Transport{Proxy: http.ProxyURL(pu)}
		trs = append(trs, tr)
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/x", nil)
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	settle(t, g0, fd0, 2, 2, 3*time.Second)
	for _, tr := range trs {
		tr.CloseIdleConnections()
	}
}

// A forwarded request whose upstream never answers: the upstream
// connection closes when the client gives up, and, while the client
// waits, when the upstream has been quiet for Idle.
func TestForwardStalledUpstream(t *testing.T) {
	t.Run("client gives up", func(t *testing.T) {
		const n = 30
		up := &ignoresEOF{}
		target := listenTCP(t, up.handle)
		t.Cleanup(up.close)
		_, pa, _ := boundedProxy(t, testLimits)
		pu, _ := url.Parse("http://" + pa)
		tr := &http.Transport{Proxy: http.ProxyURL(pu)}
		defer tr.CloseIdleConnections()
		cl := &http.Client{Transport: tr}
		g0, fd0 := usage()
		// The client gives up once every request has reached the
		// upstream, so each one tests the proxy's close, not whether a
		// busy runner dialled it before a timeout.
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var wg sync.WaitGroup
		for range n {
			wg.Go(func() {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target+"/x", nil)
				if resp, err := cl.Do(req); err == nil {
					resp.Body.Close()
				}
			})
		}
		for wait := time.Now().Add(10 * time.Second); up.accepted() < n && time.Now().Before(wait); {
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		wg.Wait()
		if got := up.accepted(); got != n {
			t.Fatalf("%d of %d requests reached the upstream", got, n)
		}
		tr.CloseIdleConnections()
		settle(t, g0, fd0, 2, n+2, 3*time.Second) // n: the upstream's side, which it keeps
		deadline := time.Now().Add(2 * time.Second)
		for up.eof.Load() < n && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if got := up.eof.Load(); got != n {
			t.Fatalf("%d of %d upstream connections closed", got, n)
		}
	})
	t.Run("client waits", func(t *testing.T) {
		up := &ignoresEOF{}
		target := listenTCP(t, up.handle)
		t.Cleanup(up.close)
		lim := testLimits
		lim.Idle = 300 * time.Millisecond
		_, pa, _ := boundedProxy(t, lim)
		pu, _ := url.Parse("http://" + pa)
		tr := &http.Transport{Proxy: http.ProxyURL(pu)}
		defer tr.CloseIdleConnections()
		g0, fd0 := usage()
		start := time.Now()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+target+"/x", nil)
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway || time.Since(start) > 3*time.Second {
			t.Fatalf("status %d after %v, want 502 after about %v", resp.StatusCode, time.Since(start), lim.Idle)
		}
		tr.CloseIdleConnections()
		settle(t, g0, fd0, 1, 2, 3*time.Second) // the upstream keeps its side
	})
}

// A forwarded body that stops partway reaches the client as broken,
// not as a complete (shorter) body.
func TestForwardBrokenBodyAborts(t *testing.T) {
	target := listenTCP(t, func(c net.Conn) {
		defer c.Close()
		_, _ = http.ReadRequest(bufio.NewReader(c))
		// More than the proxy buffers, so the client has the header and
		// part of the body; then nothing, until the proxy closes it as idle.
		part := strings.Repeat("x", 16<<10)
		_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n", len(part), part)
		_, _ = io.Copy(io.Discard, c)
	})
	lim := testLimits
	lim.Idle = 300 * time.Millisecond
	_, pa, _ := boundedProxy(t, lim)
	pu, _ := url.Parse("http://" + pa)
	tr := &http.Transport{Proxy: http.ProxyURL(pu)}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+target+"/x", nil)
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err == nil {
		t.Fatalf("the body (%d bytes) ended cleanly; it was cut off", len(b))
	}
}

// Past MaxFlows a connection is refused with 503 and logged; once one
// closes, another is let through.
func TestMaxFlows(t *testing.T) {
	target := listenTCP(t, echoConn)
	lim := testLimits
	lim.MaxFlows = 2
	p, pa, path := boundedProxy(t, lim)
	a, _, codeA := connectVia(t, pa, target)
	defer a.Close()
	b, _, codeB := connectVia(t, pa, target)
	defer b.Close()
	c, _, codeC := connectVia(t, pa, target)
	c.Close()
	if codeA != http.StatusOK || codeB != http.StatusOK || codeC != http.StatusServiceUnavailable {
		t.Fatalf("CONNECTs: %d %d %d, want 200 200 503", codeA, codeB, codeC)
	}
	a.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		p.mu.Lock()
		n := len(p.flows)
		p.mu.Unlock()
		if n < 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	d, _, codeD := connectVia(t, pa, target)
	d.Close()
	if codeD != http.StatusOK {
		t.Fatalf("CONNECT after one closed: %d", codeD)
	}
	effs, _ := effects.Read(path)
	var refused int
	for _, e := range effs {
		if e.Verdict == "deny" && e.Reason == "too many open connections" {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("%d refusals logged, want 1: %+v", refused, effs)
	}
}

// A connection to the proxy that sends no request is not a flow:
// MaxFlows does not count it. Past twice MaxFlows such connections, one
// more is closed at once; once some close, new ones are served again.
func TestMaxConns(t *testing.T) {
	lim := testLimits
	lim.MaxFlows = 2
	const most = 4
	_, pa, _ := boundedProxy(t, lim)
	g0, fd0 := usage()
	dial := func() net.Conn {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", pa)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	// served reports whether the proxy answers a request on c (a host
	// it refuses: no upstream needed) rather than closing c.
	served := func(c net.Conn) bool {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.WriteString(c, "GET http://host.invalid/ HTTP/1.1\r\nHost: host.invalid\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("the proxy neither answered nor closed the connection: %v", err)
		}
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusForbidden
	}
	var idle []net.Conn
	for range most {
		idle = append(idle, dial()) // accepted in order, before the ones below
	}
	for i := range 3 {
		c := dial()
		if served(c) {
			t.Fatalf("connection %d past the %d idle ones was served", i+1, most)
		}
		c.Close()
	}
	if !served(idle[0]) {
		t.Fatal("a connection within the cap was closed")
	}
	for _, c := range idle {
		c.Close()
	}
	settle(t, g0, fd0, 1, 1, 3*time.Second)
	idle = idle[:0]
	for range most {
		idle = append(idle, dial())
	}
	for i, c := range idle {
		if !served(c) {
			t.Fatalf("connection %d, after the others closed, was not served", i+1)
		}
		c.Close()
	}
	settle(t, g0, fd0, 1, 1, 3*time.Second)
}

// openFlows is how many flows p holds, once it is down to want or d
// has passed.
func openFlows(p *Proxy, want int, d time.Duration) int {
	deadline := time.Now().Add(d)
	for {
		p.mu.Lock()
		n := len(p.flows)
		p.mu.Unlock()
		if n <= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// testClock moves only when the test moves it: flows that measure quiet
// by it (Proxy.now) do not count a pause of a busy runner.
type testClock struct{ ns atomic.Int64 }

func (c *testClock) now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *testClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

// A forwarded response the client stops reading: the copy blocks in a
// write to the client, and closing the upstream as idle does not end
// it. The flow's write deadline does: the slot and the client's
// connection are let go.
func TestForwardClientStopsReading(t *testing.T) {
	target := listenTCP(t, func(c net.Conn) {
		defer c.Close()
		_, _ = http.ReadRequest(bufio.NewReader(c))
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 1099511627776\r\n\r\n")
		chunk := bytes.Repeat([]byte("x"), 64<<10)
		for {
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
	})
	lim := testLimits
	lim.Idle = 300 * time.Millisecond
	p, pa, _ := boundedProxy(t, lim)
	c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", pa)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET http://"+target+"/x HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	if _, err := io.ReadFull(c, make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	// The client reads no more.
	if n := openFlows(p, 0, 5*time.Second); n != 0 {
		t.Fatalf("%d flows open after the client stopped reading for 5s, want 0 (Idle %v)", n, lim.Idle)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.Copy(io.Discard, c)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("the proxy kept the client's connection open")
	}
}

// A forwarded request whose client stops sending its body: the
// transport waits in a read from the client, which closing the upstream
// as idle does not end. The flow's read deadline does: the client is
// answered and the slot let go. A body that keeps coming, however
// slowly, goes on past Idle.
func TestForwardClientStallsBody(t *testing.T) {
	// echoBody answers each request with its body; got counts the body
	// bytes it has read, as they arrive.
	echoBody := func(t *testing.T, got *atomic.Int64) string {
		return listenTCP(t, func(c net.Conn) {
			defer c.Close()
			req, err := http.ReadRequest(bufio.NewReader(c))
			if err != nil {
				return
			}
			var b []byte
			for one := make([]byte, 1); ; { // to the end, or until the proxy closes
				n, err := req.Body.Read(one)
				b = append(b, one[:n]...)
				got.Add(int64(n))
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return
				}
			}
			_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(b), b)
		})
	}
	target := echoBody(t, new(atomic.Int64))
	lim := testLimits
	lim.Idle = 300 * time.Millisecond
	p, pa, _ := boundedProxy(t, lim)
	post := func(t *testing.T, pa, target string, length int) (net.Conn, *bufio.Reader) {
		t.Helper()
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", pa)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(c, "POST http://%s/x HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", target, target, length)
		return c, bufio.NewReader(c)
	}
	t.Run("stalls", func(t *testing.T) {
		g0, fd0 := usage()
		c, br := post(t, pa, target, 1000000)
		defer c.Close()
		_, _ = io.WriteString(c, "abc") // and no more
		start := time.Now()
		_ = c.SetReadDeadline(start.Add(5 * time.Second))
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("no answer %v after the body stalled (Idle %v): %v", time.Since(start), lim.Idle, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway || time.Since(start) > 3*time.Second {
			t.Fatalf("status %d after %v, want 502 after about %v", resp.StatusCode, time.Since(start), lim.Idle)
		}
		if n := openFlows(p, 0, 2*time.Second); n != 0 {
			t.Fatalf("%d flows open, want 0", n)
		}
		c.Close()
		settle(t, g0, fd0, 1, 1, 3*time.Second)
	})
	t.Run("progresses", func(t *testing.T) {
		// The flows measure quiet by a clock that moves Idle/4 once each
		// byte has reached the upstream: a pause of a busy runner is not
		// the client's quiet. The bytes still come Idle/4 apart in real
		// time too. KeepAlive is not under test; such a pause must not
		// close the connection before the next request either.
		var got atomic.Int64
		target := echoBody(t, &got)
		clk := &testClock{}
		plim := lim
		plim.KeepAlive = KeepAliveIdle
		_, pa, _ := boundedProxyVia(t, plim, "", func(p *Proxy) { p.now = clk.now })
		const n = 12 // a byte each Idle/4: 3×Idle
		c, br := post(t, pa, target, n)
		defer c.Close()
		start := time.Now()
		for i := range n {
			if i > 0 {
				time.Sleep(lim.Idle / 4)
			}
			_, _ = io.WriteString(c, "x")
			for deadline := time.Now().Add(5 * time.Second); got.Load() <= int64(i); time.Sleep(time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatalf("byte %d of the body did not reach the upstream", i+1)
				}
			}
			clk.advance(lim.Idle / 4)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("no answer after %v: %v", time.Since(start), err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(b) != strings.Repeat("x", n) {
			t.Fatalf("a body sent slowly for %v: status %d, %q %v", time.Since(start), resp.StatusCode, b, err)
		}
		// The read deadline is let go with the request: the connection
		// serves the next one.
		_, _ = fmt.Fprintf(c, "POST http://%s/x HTTP/1.1\r\nHost: %s\r\nContent-Length: 2\r\n\r\nok", target, target)
		resp, err = http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("no answer to the next request: %v", err)
		}
		b, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(b) != "ok" {
			t.Fatalf("the next request on the connection: status %d, %q %v", resp.StatusCode, b, err)
		}
	})
}

// An upstream proxy that takes the CONNECT and never answers it: the
// tunnel's flow owns that connection from the dial on, so it is closed
// as idle, or by a cut, and the agent is answered.
func TestUpstreamProxyNeverAnswers(t *testing.T) {
	for _, tc := range []struct {
		name string
		idle time.Duration
		cut  bool
	}{{"idle", 300 * time.Millisecond, false}, {"cut", time.Hour, true}} {
		t.Run(tc.name, func(t *testing.T) {
			var accepted atomic.Int32
			hung := listenTCP(t, func(c net.Conn) {
				defer c.Close()
				stop := context.AfterFunc(t.Context(), func() { c.Close() }) // a failing run ends too
				defer stop()
				accepted.Add(1)
				_, _ = io.Copy(io.Discard, c) // reads the CONNECT, never answers
			})
			lim := testLimits
			lim.Idle = tc.idle
			p, pa, _ := boundedProxyVia(t, lim, hung, nil)
			c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", pa)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.WriteString(c, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
			if tc.cut {
				deadline := time.Now().Add(2 * time.Second)
				for accepted.Load() == 0 {
					if time.Now().After(deadline) {
						t.Fatal("the upstream proxy was not dialled")
					}
					time.Sleep(10 * time.Millisecond)
				}
				p.Cut(Allowlist{}, "test")
			}
			resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatalf("no answer to CONNECT: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("CONNECT through an upstream proxy that never answered: %d, want 403 (the connection was cut)", resp.StatusCode)
			}
			if n := openFlows(p, 0, 2*time.Second); n != 0 {
				t.Fatalf("%d flows open, want 0", n)
			}
		})
	}
}

// A forwarded request whose flow stopped (here: a silent upstream, idle)
// is the connection's last: the next request on it either finds it
// closed or is served, never answered for a context the stop canceled.
func TestForwardStoppedFlowEndsTheConnection(t *testing.T) {
	silent := listenTCP(t, func(c net.Conn) {
		defer c.Close()
		_, _ = io.Copy(io.Discard, c) // reads the request, never answers
	})
	good := listenTCP(t, func(c net.Conn) {
		defer c.Close()
		br := bufio.NewReader(c)
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
	})
	lim := testLimits
	lim.Idle = 300 * time.Millisecond
	_, pa, _ := boundedProxy(t, lim)
	for name, first := range map[string]string{
		"get":  "GET http://" + silent + "/ HTTP/1.1\r\nHost: " + silent + "\r\n\r\n",
		"post": "POST http://" + silent + "/ HTTP/1.1\r\nHost: " + silent + "\r\nContent-Length: 2\r\n\r\nok",
	} {
		t.Run(name, func(t *testing.T) {
			c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", pa)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			br := bufio.NewReader(c)
			_, _ = io.WriteString(c, first)
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("no answer for the stopped flow: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway || !resp.Close {
				t.Fatalf("stopped flow: status %d close %v, want 502 and the connection's last", resp.StatusCode, resp.Close)
			}
			for range 3 {
				_, _ = io.WriteString(c, "GET http://"+good+"/ HTTP/1.1\r\nHost: "+good+"\r\n\r\n")
				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					return // closed: the client opens a new connection
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("a later request on the connection: %d %q", resp.StatusCode, b)
				}
			}
		})
	}
}

// slowLog is a log whose writes are slow, as on a busy disk or behind
// another writer: an allow entry for a connection takes d, of real time
// and of clk, which the proxy's flows may measure quiet by. writing says
// when one has started.
type slowLog struct {
	audit.Recorder
	d       time.Duration
	clk     testClock
	writing chan struct{}
}

func (l *slowLog) Add(e audit.Event) {
	if e.Kind == "net.egress" && e.Verdict == "allow" {
		select {
		case l.writing <- struct{}{}:
		default:
		}
		l.clk.advance(l.d)
		time.Sleep(l.d) // a timer that counts the write fires while it lasts
	}
	l.Recorder.Add(e)
}

// The proxy's own time before it hands a connection on, here a log write
// longer than Idle, is not quiet on the connection. It was counted: the
// flow stopped before the proxy held anything, a host that would have
// answered was refused as cut, and a silent one got 403 or 502 by how
// long the write took. Only a cut stops the flow in that time.
func TestSlowLogIsNotIdle(t *testing.T) {
	good := listenTCP(t, func(c net.Conn) {
		defer c.Close()
		br := bufio.NewReader(c)
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
	})
	silent := listenTCP(t, func(c net.Conn) {
		defer c.Close()
		_, _ = io.Copy(io.Discard, c) // reads the request, never answers
	})
	echoed := listenTCP(t, echoConn)
	lim := testLimits
	lim.Idle = 300 * time.Millisecond
	// slowly serves through a slowLog. With clk, which only the log
	// moves, a connection the proxy has handed on is never quiet, so a
	// busy runner cannot fail an exchange that should pass; without, a
	// silent upstream is quiet as it is in use.
	slowly := func(sl *slowLog, clk bool) func(*Proxy) {
		return func(p *Proxy) {
			p.Limits = lim
			sl.Recorder, p.Log = p.Log, sl
			if clk {
				p.now = sl.clk.now
			}
		}
	}
	slowProxy := func(t *testing.T, clk bool) (*Proxy, string, *slowLog) {
		t.Helper()
		sl := &slowLog{d: 2 * lim.Idle, writing: make(chan struct{}, 1)}
		p, pa, _ := boundedProxyVia(t, lim, "", slowly(sl, clk))
		return p, pa, sl
	}
	// ask sends req to the proxy at pa: the answer's status and body,
	// and whether it is the connection's last.
	ask := func(t *testing.T, pa, req string) (int, string, bool) {
		t.Helper()
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", pa)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(c, req)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("no answer: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b), resp.Close
	}
	get := func(host string) string { return "GET http://" + host + "/ HTTP/1.1\r\nHost: " + host + "\r\n\r\n" }
	t.Run("forward", func(t *testing.T) {
		t.Parallel()
		_, pa, _ := slowProxy(t, true)
		if code, body, _ := ask(t, pa, get(good)); code != http.StatusOK || body != "ok" {
			t.Fatalf("a host that answers: %d %q, want 200", code, body)
		}
	})
	t.Run("silent upstream", func(t *testing.T) {
		t.Parallel()
		_, pa, _ := slowProxy(t, false)
		code, body, last := ask(t, pa, "POST http://"+silent+"/ HTTP/1.1\r\nHost: "+silent+"\r\nContent-Length: 2\r\n\r\nok")
		if code != http.StatusBadGateway || !last {
			t.Fatalf("a silent host: %d %q close %v, want 502 and the connection's last, as with a quick log", code, body, last)
		}
	})
	t.Run("connect", func(t *testing.T) {
		t.Parallel()
		_, pa, _ := slowProxy(t, true)
		c, br, code := connectVia(t, pa, echoed)
		defer c.Close()
		if code != http.StatusOK {
			t.Fatalf("CONNECT: %d, want 200", code)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(c, "ping")
		if b, err := io.ReadAll(io.LimitReader(br, 4)); err != nil || string(b) != "ping" {
			t.Fatalf("through the tunnel: %q %v", b, err)
		}
	})
	t.Run("intercept", func(t *testing.T) {
		t.Parallel()
		up, _ := echo(t)
		sl := &slowLog{d: 2 * lim.Idle, writing: make(chan struct{}, 1)}
		c, _, _ := mitmProxyWith(t, up, "", slowly(sl, true))
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, up.URL+"/", nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("an intercepted host: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("an intercepted host: %d, want 200", resp.StatusCode)
		}
	})
	t.Run("cut", func(t *testing.T) {
		t.Parallel()
		p, pa, sl := slowProxy(t, false)
		go func() {
			select {
			case <-sl.writing:
				p.Cut(Allowlist{}, "test")
			case <-t.Context().Done():
			}
		}()
		if code, body, _ := ask(t, pa, get(good)); code != http.StatusForbidden || !strings.Contains(body, "was cut") {
			t.Fatalf("a cut while the request was logged: %d %q, want 403", code, body)
		}
	})
}

// deadlineWriter counts the read deadlines set on it through a
// ResponseController.
type deadlineWriter struct {
	http.ResponseWriter
	set int
}

func (d *deadlineWriter) SetReadDeadline(time.Time) error { d.set++; return nil }

// readStop fires only while live, and says whether it fired.
func TestReadStop(t *testing.T) {
	w := &deadlineWriter{ResponseWriter: httptest.NewRecorder()}
	s := &readStop{rc: http.NewResponseController(w), live: true}
	_ = s.Close()
	if w.set != 1 || !s.end() {
		t.Fatalf("live: %d deadlines, fired %v", w.set, s.fired)
	}
	w.set = 0
	s = &readStop{rc: http.NewResponseController(w), live: true}
	if s.end() {
		t.Fatal("reported fired before it was")
	}
	_ = s.Close()
	if w.set != 0 {
		t.Fatalf("set a deadline after end: %d", w.set)
	}
}

// A response whose headers the socket cannot take while the client does
// not read is still bounded: it is flushed while the flow can stop it,
// so the connection does not stay pinned after the handler.
func TestForwardUnreadHeadersAreBounded(t *testing.T) {
	big := strings.Repeat("x", 8<<20) // more than the socket buffers hold
	target := listenTCP(t, func(c net.Conn) {
		defer c.Close()
		if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
			return
		}
		_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nX-Big: %s\r\nContent-Length: 0\r\n\r\n", big)
	})
	lim := testLimits
	lim.Idle = 300 * time.Millisecond
	_, pa, _ := boundedProxy(t, lim)
	g0, fd0 := usage()
	c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", pa)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	_, _ = fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	// The proxy takes the request and writes to a client that never
	// reads. Wait until its side of the connection is busy, then for it
	// to let go: what stays is this test's own end of the connection.
	deadline := time.Now().Add(2 * time.Second)
	for g, _ := usage(); g <= g0 && time.Now().Before(deadline); g, _ = usage() {
		time.Sleep(5 * time.Millisecond)
	}
	settle(t, g0, fd0, 0, 1, 5*time.Second)
}

// A forward whose flow has stopped before it begins answers as the
// connection's last: a body's read deadline may already be set.
func TestForwardOnStoppedFlowCloses(t *testing.T) {
	p := &Proxy{}
	f := &flow{}
	f.stop()
	for _, body := range []io.Reader{strings.NewReader("ok"), nil} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://example.test/", body)
		if body == nil {
			r = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.test/", nil)
		}
		w := httptest.NewRecorder()
		p.forward(w, r, "example.test", f)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status %d", w.Code)
		}
		if w.Header().Get("Connection") != "close" {
			t.Fatalf("a body's forward on a stopped flow: headers %v", w.Header())
		}
	}
}

// deadlines is a ResponseWriter that records the write deadlines set
// on it through a ResponseController.
type deadlines struct {
	*httptest.ResponseRecorder
	set, reads []time.Time
}

func (d *deadlines) SetWriteDeadline(t time.Time) error { d.set = append(d.set, t); return nil }
func (d *deadlines) SetReadDeadline(t time.Time) error  { d.reads = append(d.reads, t); return nil }

// The proxy's own answers, which have no flow to close them, are
// written within AnswerWrite; a request starts with no deadline.
func TestAnswerHasWriteDeadline(t *testing.T) {
	log, _ := newLog(t)
	p := New(Allowlist{"api.anthropic.com"}, log)
	for _, target := range []string{"http://paste.example.net/", "http://api.anthropic.com:1/", "http://[::1/"} {
		w := &deadlines{ResponseRecorder: httptest.NewRecorder()}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x/", nil)
		r.URL, _ = url.Parse(target)
		if r.URL == nil {
			r.URL = &url.URL{Scheme: "http", Host: "[::1"}
		}
		before := time.Now()
		p.ServeHTTP(w, r)
		if w.Code < 400 {
			t.Fatalf("%s: %d", target, w.Code)
		}
		if len(w.set) != 2 || !w.set[0].IsZero() || w.set[1].Before(before) || w.set[1].After(time.Now().Add(AnswerWrite)) {
			t.Errorf("%s: deadlines %v", target, w.set)
		}
		// What is left of the body is read after the answer, within
		// AnswerWrite too.
		if len(w.reads) != 1 || w.reads[0].Before(before.Add(AnswerWrite)) || w.reads[0].After(time.Now().Add(AnswerWrite)) {
			t.Errorf("%s: read deadlines %v", target, w.reads)
		}
	}
}

// paceLog records, in order, the write deadlines set on an answer and
// the writes made to it.
type paceLog struct {
	*httptest.ResponseRecorder
	ev []string
	at []time.Time
}

func (l *paceLog) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		l.ev = append(l.ev, "clear")
	} else {
		l.ev, l.at = append(l.ev, "d"), append(l.at, t)
	}
	return nil
}

func (l *paceLog) SetReadDeadline(t time.Time) error {
	l.ev, l.at = append(l.ev, "r"), append(l.at, t)
	return nil
}

func (l *paceLog) WriteHeader(code int) {
	l.ev = append(l.ev, "h")
	l.ResponseRecorder.WriteHeader(code)
}

func (l *paceLog) Write(b []byte) (int, error) {
	l.ev = append(l.ev, "w"+strconv.Itoa(len(b)))
	return l.ResponseRecorder.Write(b)
}

// The mirror's answers have no flow either: every write to the socket,
// at most pacedChunk of an answer, has a deadline of AnswerWrite set
// just before it, and so does what net/http writes after the mirror
// returns.
func TestMirrorAnswerIsPaced(t *testing.T) {
	big := 3*pacedChunk + 1
	cases := []struct {
		name  string
		body  string
		serve func(http.ResponseWriter)
		want  string
	}{
		{"header and body", "", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(make([]byte, big))
		}, "clear d h d w65536 d w65536 d w65536 d w1 d"},
		{"body only", "", func(w http.ResponseWriter) { _, _ = w.Write(make([]byte, 10)) }, "clear d w10 d"},
		{"header only", "", func(w http.ResponseWriter) { w.WriteHeader(http.StatusOK) }, "clear d h d"},
		{"empty write", "", func(w http.ResponseWriter) { _, _ = w.Write(nil) }, "clear d w0 d"},
		// A request body, which the mirror leaves unread, is read after
		// the answer within AnswerWrite.
		{"request body", "0123456789", func(w http.ResponseWriter) { _, _ = w.Write(make([]byte, 10)) }, "clear d w10 d r"},
	}
	for _, c := range cases {
		log, _ := newLog(t)
		p := New(nil, log)
		p.Mirror = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { c.serve(w) })
		w := &paceLog{ResponseRecorder: httptest.NewRecorder()}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://airbag.mirror/npm/x", strings.NewReader(c.body))
		if c.body == "" {
			r.ContentLength, r.Body = 0, http.NoBody
		}
		before := time.Now()
		p.ServeHTTP(w, r)
		if got := strings.Join(w.ev, " "); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
		for _, d := range w.at {
			if d.Before(before.Add(AnswerWrite)) || d.After(time.Now().Add(AnswerWrite)) {
				t.Errorf("%s: deadline %v", c.name, d)
			}
		}
	}
}

// A request that declares a body and sends none still gets the
// proxy's own answer, a refusal or the mirror's: net/http would first
// read the body, with no deadline.
func TestAnswerToUnsentBody(t *testing.T) {
	log, _ := newLog(t)
	p := New(Allowlist{"api.anthropic.com"}, log)
	p.Mirror = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() { _ = p.Serve(l) }()
	g0, fd0 := usage()
	for target, want := range map[string]int{"paste.example.net": http.StatusForbidden, "airbag.mirror": http.StatusOK} {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second)) // a failing run ends too
		_, _ = fmt.Fprintf(c, "POST http://%s/x HTTP/1.1\r\nHost: %s\r\nContent-Length: 10\r\n\r\n", target, target)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Errorf("%s: %v", target, err)
		} else {
			if resp.StatusCode != want || !resp.Close {
				t.Errorf("%s: %d, close %v", target, resp.StatusCode, resp.Close)
			}
			resp.Body.Close()
		}
		c.Close()
	}
	// The proxy lets go of both connections once they are closed.
	settle(t, g0, fd0, 0, 0, 3*time.Second)
}

// Cut closes every flow before it writes the log, which another writer
// may hold up: a secret read waits for the closes, not for the log.
func TestCutClosesBeforeLogging(t *testing.T) {
	target := listenTCP(t, echoConn)
	p, addr, path := boundedProxy(t, DefaultLimits())
	var cs []net.Conn
	for range 3 {
		c, _, code := connectVia(t, addr, target)
		t.Cleanup(func() { c.Close() })
		if code != http.StatusOK {
			t.Fatalf("CONNECT: %d", code)
		}
		cs = append(cs, c)
	}
	// Another writer holds the database: the log's writes wait for it.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	cut := make(chan struct{})
	go func() { p.Cut(nil, "test"); close(cut) }()
	for i, c := range cs {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Errorf("flow %d open while the log was held: %v", i, err)
		}
	}
	if _, err := conn.ExecContext(t.Context(), "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	<-cut
}
