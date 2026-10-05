package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// The proxy and the tcp:// forwards run on the host side: their
// goroutines, file descriptors and memory are the host's, and the agent
// decides how many connections it opens and how long it keeps them. So
// each connection is closed once it stops carrying data, and the number
// open at once is capped.
const (
	// TunnelIdle closes a CONNECT tunnel or an intercepted connection on
	// which no byte has moved either way for this long, and a forwarded
	// request whose upstream has been quiet as long. Fifteen minutes, as
	// Squid's read_timeout: servers and load balancers on the way close
	// quiet connections sooner, so a client that keeps one open (a
	// websocket, an event stream) already sends something more often.
	TunnelIdle = 15 * time.Minute
	// ForwardIdle is TunnelIdle for tcp:// forwards. They carry the pools
	// of database and cache clients, which keep connections idle for a
	// long time: an hour, as Envoy's TCP proxy.
	ForwardIdle = time.Hour
	// Drain bounds the wait once one side of a connection has finished
	// sending: it is closed when the other side has then been quiet this
	// long. A peer that ignores the end does not keep it open; one that
	// is still sending its answer goes on.
	Drain = 30 * time.Second
	// KeepAliveIdle closes an HTTP connection, to the proxy or
	// intercepted, that has waited this long for its next request, as
	// Squid's client_idle_pconn_timeout. Clients open a new one.
	KeepAliveIdle = 2 * time.Minute
	// MaxFlows caps the connections one session holds open through the
	// proxy at once: tunnels, intercepted connections and forwarded
	// requests. A browser keeps at most 32 to one proxy; package
	// managers fetch through the mirror, which is not counted. The
	// connections to the proxy itself, which include those waiting for
	// a request, are capped at twice as many (Proxy.Serve).
	MaxFlows = 512
)

// Limits are the bounds a Proxy applies; New sets the defaults above,
// tests shorten them.
type Limits struct {
	Idle, Drain, KeepAlive time.Duration
	MaxFlows               int
}

// DefaultLimits are the limits New gives a Proxy.
func DefaultLimits() Limits {
	return Limits{Idle: TunnelIdle, Drain: Drain, KeepAlive: KeepAliveIdle, MaxFlows: MaxFlows}
}

// A flow is one connection relayed for the agent, with the
// connections that serve it. It is stopped (all of them closed) when it
// has been quiet for idle, or for drain once one side has finished
// sending, or when the session cuts it. A timer checks the quiet; no
// goroutine waits for it.
type flow struct {
	host, target string // for Cut and its log
	idle, drain  time.Duration
	start        time.Time
	last         atomic.Int64 // time since start when a byte last moved

	mu      sync.Mutex
	conns   map[io.Closer]bool
	half    bool // one side has finished sending
	stopped bool
	timer   *time.Timer
}

func newFlow(idle, drain time.Duration) *flow {
	f := &flow{idle: idle, drain: drain, start: time.Now(), conns: map[io.Closer]bool{}}
	f.mu.Lock() // check waits until f.timer is set
	if idle > 0 {
		f.timer = time.AfterFunc(idle, f.check)
	}
	f.mu.Unlock()
	return f
}

// touch records that a byte moved.
func (f *flow) touch() { f.last.Store(int64(time.Since(f.start))) }

// limit is how long the flow may stay quiet now; 0 is no limit.
func (f *flow) limit() time.Duration {
	if f.half && f.drain > 0 && (f.idle <= 0 || f.drain < f.idle) {
		return f.drain
	}
	return f.idle
}

// check runs when the timer fires: it stops a flow that has been quiet
// for its limit, or sets the timer again for when it would be. The
// quiet is measured and the flow marked stopped under one lock, so
// nothing else stops or holds in between; a byte that moves after that
// moved after the limit ran out.
func (f *flow) check() {
	f.mu.Lock()
	lim := f.limit()
	if f.stopped || lim <= 0 {
		f.mu.Unlock()
		return
	}
	if quiet := time.Since(f.start) - time.Duration(f.last.Load()); quiet < lim {
		f.timer.Reset(lim - quiet)
		f.mu.Unlock()
		return
	}
	cs := f.stopLocked()
	f.mu.Unlock()
	closeAll(cs)
}

// halfClose records that one side has finished sending: from now on
// the other has drain to go quiet in.
func (f *flow) halfClose() {
	f.touch()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.half || f.stopped {
		return
	}
	f.half = true
	lim := f.limit()
	switch {
	case lim <= 0:
	case f.timer == nil:
		f.timer = time.AfterFunc(lim, f.check)
	default:
		f.timer.Reset(lim)
	}
}

// hold adds c to what stopping the flow closes. A flow that has
// stopped already closes c at once and says false.
func (f *flow) hold(c io.Closer) bool {
	f.mu.Lock()
	if f.stopped {
		f.mu.Unlock()
		_ = c.Close()
		return false
	}
	f.conns[c] = true
	f.mu.Unlock()
	return true
}

func (f *flow) release(c io.Closer) {
	f.mu.Lock()
	delete(f.conns, c)
	f.mu.Unlock()
}

// isStopped reports whether the flow has stopped.
func (f *flow) isStopped() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopped
}

// stop closes the flow's connections. It reports whether this call
// stopped it, rather than an earlier one.
func (f *flow) stop() bool {
	f.mu.Lock()
	if f.stopped {
		f.mu.Unlock()
		return false
	}
	cs := f.stopLocked()
	f.mu.Unlock()
	closeAll(cs)
	return true
}

// stopLocked marks the flow stopped and hands back its connections for
// closing once f.mu is released. f.mu is held.
func (f *flow) stopLocked() map[io.Closer]bool {
	f.stopped = true
	if f.timer != nil {
		f.timer.Stop()
	}
	cs := f.conns
	f.conns = nil
	return cs
}

func closeAll(cs map[io.Closer]bool) {
	for c := range cs {
		_ = c.Close()
	}
}

// closer closes by calling its func: a flow holds it to cancel a
// request.
type closer struct{ f func() }

func (c *closer) Close() error { c.f(); return nil }

// readStop ends a blocked read of a request body with a read deadline in
// the past on the client connection, while live; once end has run it
// does nothing, so it cannot reach the connection's next request.
type readStop struct {
	mu          sync.Mutex
	rc          *http.ResponseController
	live, fired bool
}

func (s *readStop) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live {
		s.fired = true
		_ = s.rc.SetReadDeadline(time.Now())
	}
	return nil
}

// end stops s from firing and reports whether it had.
func (s *readStop) end() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.live = false
	return s.fired
}

var errStopped = errors.New("airbag: the connection was closed (cut, or idle too long)")

// dialer wraps dial so that each connection it opens belongs to the
// flow: its bytes mark the flow active, and stopping the flow closes it.
func (f *flow) dialer(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		wc := &watchedConn{Conn: c, f: f}
		if !f.hold(wc) {
			return nil, errStopped
		}
		return wc, nil
	}
}

// bufs hold the bytes in flight. Each direction of an open connection
// holds one while it waits to read, so they are one TLS record (16 KiB)
// rather than io.Copy's 32 KiB; io.Copy's splice is given up, since it
// would not say when bytes moved.
var bufs = sync.Pool{New: func() any { b := make([]byte, 16<<10); return &b }}

// copy copies src to dst until src ends (nil) or either side fails,
// marking the flow active as bytes move.
func (f *flow) copy(dst io.Writer, src io.Reader) error {
	bp := bufs.Get().(*[]byte)
	defer bufs.Put(bp)
	buf := *bp
	for {
		n, err := src.Read(buf)
		if n > 0 {
			f.touch()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
			f.touch()
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// pipe relays between a (read through ar, which may hold bytes a sent
// already) and b until both directions end, then closes both. When one
// direction ends, the side it wrote to is told (a half-close) and the
// drain bound starts; when one fails, or the flow stops, both close.
func (f *flow) pipe(a net.Conn, ar io.Reader, b net.Conn) {
	if !f.hold(a) || !f.hold(b) { // stopped already
		_ = a.Close()
		_ = b.Close()
		return
	}
	var wg sync.WaitGroup
	one := func(dst net.Conn, src io.Reader) {
		defer wg.Done()
		if err := f.copy(dst, src); err != nil {
			f.stop()
			return
		}
		closeWrite(dst)
		f.halfClose()
	}
	wg.Add(2)
	go one(b, ar)
	go one(a, b)
	wg.Wait()
	f.stop()
}

// Relay relays bytes both ways between a and b, as a CONNECT tunnel
// does, until both directions end, then closes both. It closes them
// sooner when no byte has moved for idle (0: no limit), or, once one
// side has finished sending, when the other has been quiet for drain.
func Relay(a, b net.Conn, idle, drain time.Duration) {
	newFlow(idle, drain).pipe(a, a, b)
}

// watchedConn marks its flow active on each byte read or written, and
// passes a half-close on to it. The intercepted connections are served
// by net/http, which does its own copying: the flow sees it through
// this.
type watchedConn struct {
	net.Conn
	f *flow
}

func (c *watchedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.f.touch()
	}
	return n, err
}

func (c *watchedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.f.touch()
	}
	return n, err
}

// CloseWrite passes a half-close on, as net/http does before it closes
// a connection or when one side of an upgraded one has finished; the
// drain bound starts.
func (c *watchedConn) CloseWrite() error {
	c.f.halfClose()
	type cw interface{ CloseWrite() error }
	if x, ok := c.Conn.(cw); ok {
		return x.CloseWrite()
	}
	return nil
}

func (c *watchedConn) Close() error {
	c.f.release(c)
	return c.Conn.Close()
}

// capListener keeps at most max of the connections it accepts open: one
// past that is closed at once, and Accept goes on to the next. Each
// connection gives its place back when it is closed, by the server or
// by the handler that hijacked it.
type capListener struct {
	net.Listener
	max  int64
	open atomic.Int64
}

func (l *capListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.open.Add(1) <= l.max {
			return &cappedConn{Conn: c, l: l}, nil
		}
		l.open.Add(-1)
		_ = c.Close()
	}
}

// cappedConn is a connection a capListener counts: the first Close
// gives its place back.
type cappedConn struct {
	net.Conn
	l    *capListener
	once sync.Once
}

func (c *cappedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.l.open.Add(-1) })
	return err
}

// CloseWrite passes a half-close on, as a tunnel does when its upstream
// has finished and net/http does before it closes a connection.
func (c *cappedConn) CloseWrite() error {
	type cw interface{ CloseWrite() error }
	if x, ok := c.Conn.(cw); ok {
		return x.CloseWrite()
	}
	return nil
}
