package proxy

import (
	"bufio"
	"bytes"
	"context"
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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

func (s *ignoresEOF) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.held {
		c.Close()
	}
}

func boundedProxy(t *testing.T, lim Limits) (*Proxy, string, string) {
	t.Helper()
	return boundedProxyVia(t, lim, "")
}

// boundedProxyVia is boundedProxy behind the upstream proxy at
// upstream ("": none).
func boundedProxyVia(t *testing.T, lim Limits, upstream string) (*Proxy, string, string) {
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
		cl := &http.Client{Transport: tr, Timeout: 200 * time.Millisecond}
		g0, fd0 := usage()
		var wg sync.WaitGroup
		for range n {
			wg.Go(func() {
				req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+target+"/x", nil)
				if resp, err := cl.Do(req); err == nil {
					resp.Body.Close()
				}
			})
		}
		wg.Wait()
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
			p, pa, _ := boundedProxyVia(t, lim, hung)
			c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", pa)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.WriteString(c, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
			if tc.cut {
				for accepted.Load() == 0 {
					time.Sleep(10 * time.Millisecond)
				}
				p.Cut(Allowlist{}, "test")
			}
			resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatalf("no answer to CONNECT: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Fatal("CONNECT succeeded through an upstream proxy that never answered")
			}
			if n := openFlows(p, 0, 2*time.Second); n != 0 {
				t.Fatalf("%d flows open, want 0", n)
			}
		})
	}
}
