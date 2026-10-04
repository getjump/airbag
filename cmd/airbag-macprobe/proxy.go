package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// connectProxy is the smallest HTTP CONNECT proxy: the stand-in for
// airbag's egress proxy on a localhost port.
type connectProxy struct {
	l    net.Listener
	mu   sync.Mutex
	seen []string // hosts asked for
}

func startProxy() (*connectProxy, error) {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &connectProxy{l: l}
	go p.serve()
	return p, nil
}

func (p *connectProxy) Port() int    { return p.l.Addr().(*net.TCPAddr).Port }
func (p *connectProxy) Close() error { return p.l.Close() }

func (p *connectProxy) Seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

func (p *connectProxy) serve() {
	for {
		c, err := p.l.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *connectProxy) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		_, _ = io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}
	p.mu.Lock()
	p.seen = append(p.seen, req.Host)
	p.mu.Unlock()
	up, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(context.Background(), "tcp", req.Host)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}
