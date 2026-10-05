// Package netcap caps the connections a listener keeps open. airbag's
// servers on the host side (the proxy, the control socket) accept
// connections the agent opens, and each one held is a goroutine and a
// file descriptor there.
package netcap

import (
	"net"
	"sync"
	"sync/atomic"
)

// Limit returns l keeping at most max of the connections it accepts
// open: one past that is closed at once, and Accept goes on to the
// next. Each connection gives its place back when it is closed, by the
// server or by the handler that hijacked it.
func Limit(l net.Listener, max int) net.Listener {
	return &listener{Listener: l, max: int64(max)}
}

type listener struct {
	net.Listener
	max  int64
	open atomic.Int64
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.open.Add(1) <= l.max {
			return &conn{Conn: c, l: l}, nil
		}
		l.open.Add(-1)
		_ = c.Close()
	}
}

// conn is a connection a listener counts: the first Close gives its
// place back.
type conn struct {
	net.Conn
	l    *listener
	once sync.Once
}

func (c *conn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.l.open.Add(-1) })
	return err
}

// CloseWrite passes a half-close on, as a tunnel does when its upstream
// has finished and net/http does before it closes a connection.
func (c *conn) CloseWrite() error {
	type cw interface{ CloseWrite() error }
	if x, ok := c.Conn.(cw); ok {
		return x.CloseWrite()
	}
	return nil
}
