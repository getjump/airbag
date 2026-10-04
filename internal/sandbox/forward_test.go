//go:build linux

package sandbox

import (
	"errors"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/taint"
)

// After a secret read, a forward to another machine refuses; one to
// this machine keeps relaying.
func TestForwarderTaint(t *testing.T) {
	log, err := effects.Open(filepath.Join(t.TempDir(), "effects.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	pol, err := policy.Load(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gate := policy.NewGate(pol, t.TempDir())
	gate.Mark(taint.Secret, ".env")

	echo, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
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
	try := func(f session.Forward) bool {
		fw := newForwarder(f, gate, log)
		a, b := net.Pipe()
		go fw.handle(b)
		defer a.Close()
		_, _ = a.Write([]byte("x"))
		buf := make([]byte, 1)
		_, err := a.Read(buf)
		return err == nil && buf[0] == 'x'
	}
	port := echo.Addr().(*net.TCPAddr).Port
	if !try(session.Forward{Host: "127.0.0.1", Port: port}) {
		t.Error("a loopback forward stopped after the secret read")
	}
	if try(session.Forward{Host: "db.example.test", Port: port}) {
		t.Error("a forward off this machine relayed after the secret read")
	}
}

func forwardTest(t *testing.T) (*policy.Gate, *effects.Log, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "effects.db")
	log, err := effects.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	pol, err := policy.Load(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return policy.NewGate(pol, t.TempDir()), log, path
}

// serveTCP serves each connection with handle until the test ends.
func serveTCP(t *testing.T, handle func(net.Conn)) (net.Listener, int) {
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
	return l, l.Addr().(*net.TCPAddr).Port
}

// startForwarder relays to 127.0.0.1:port, served on a loopback
// listener as the sandbox's bridge reaches it; adjust sets its bounds.
func startForwarder(t *testing.T, port int, adjust func(*forwarder)) (*forwarder, string) {
	t.Helper()
	gate, log, _ := forwardTest(t)
	fw := newForwarder(session.Forward{Host: "127.0.0.1", Port: port}, gate, log)
	if adjust != nil {
		adjust(fw)
	}
	var wg sync.WaitGroup
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { fw.handle(c) })
		}
	})
	return fw, l.Addr().String()
}

func dialTCP(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func goroutinesBack(t *testing.T, g0 int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for runtime.NumGoroutine() > g0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > g0 {
		t.Fatalf("goroutines %d after %v, baseline %d", g, d, g0)
	}
}

// When the agent finishes sending, the target is told and its answer
// still comes back, as a protocol that half-closes expects.
func TestForwarderHalfClose(t *testing.T) {
	_, port := serveTCP(t, func(c net.Conn) {
		defer c.Close()
		b, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("got "), b...))
	})
	_, addr := startForwarder(t, port, nil)
	c := dialTCP(t, addr)
	defer c.Close()
	_, _ = c.Write([]byte("request"))
	_ = c.(*net.TCPConn).CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b, err := io.ReadAll(c); err != nil || string(b) != "got request" {
		t.Fatalf("answer after the half-close: %q %v", b, err)
	}
}

// A target that ignores the agent's end does not keep the relay: it
// closes once the target has been quiet for drain.
func TestForwarderDrain(t *testing.T) {
	var mu sync.Mutex
	var held []net.Conn
	_, port := serveTCP(t, func(c net.Conn) {
		mu.Lock()
		held = append(held, c)
		mu.Unlock()
		_, _ = io.Copy(io.Discard, c) // to the end, then silent and open
	})
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
	_, addr := startForwarder(t, port, func(fw *forwarder) { fw.drain = 200 * time.Millisecond })
	g0 := runtime.NumGoroutine()
	for range 20 {
		c := dialTCP(t, addr)
		_, _ = c.Write([]byte("data"))
		c.Close()
	}
	goroutinesBack(t, g0, 3*time.Second)
}

// A forwarded connection with no byte either way for idle is closed;
// one that keeps carrying data is not.
func TestForwarderIdle(t *testing.T) {
	_, port := serveTCP(t, func(c net.Conn) {
		_, _ = io.Copy(struct{ io.Writer }{c}, struct{ io.Reader }{c})
		c.Close()
	})
	const idle = 300 * time.Millisecond
	_, addr := startForwarder(t, port, func(fw *forwarder) { fw.idle = idle })
	quiet := dialTCP(t, addr)
	defer quiet.Close()
	busy := dialTCP(t, addr)
	defer busy.Close()
	buf := make([]byte, 5)
	start := time.Now()
	for time.Since(start) < 3*idle {
		_, _ = busy.Write([]byte("ping\n"))
		_ = busy.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.ReadFull(busy, buf); err != nil {
			t.Fatalf("the busy forward broke after %v: %v", time.Since(start), err)
		}
		time.Sleep(idle / 4)
	}
	_ = quiet.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := quiet.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("the quiet forward is still open after %v: %v", time.Since(start), err)
	}
}

// Past max connections at once, one more is refused and logged.
func TestForwarderCap(t *testing.T) {
	_, port := serveTCP(t, func(c net.Conn) {
		_, _ = io.Copy(struct{ io.Writer }{c}, struct{ io.Reader }{c})
		c.Close()
	})
	gate, log, path := forwardTest(t)
	fw := newForwarder(session.Forward{Host: "127.0.0.1", Port: port}, gate, log)
	fw.max = 1
	first, a := net.Pipe()
	defer first.Close()
	go fw.handle(a)
	_, _ = first.Write([]byte("x"))
	if _, err := first.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	second, b := net.Pipe()
	defer second.Close()
	fw.handle(b) // refused: returns at once
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection past the cap was relayed")
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	effs, _ := effects.Read(path)
	var refused int
	for _, e := range effs {
		if e.Kind == "net.tcp" && e.Verdict == "deny" && e.Reason == "too many open connections" {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("%d refusals logged, want 1: %+v", refused, effs)
	}
}
