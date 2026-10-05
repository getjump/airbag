package sandbox

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/models"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/session"
)

// forwarder relays the agent's connections to a tcp:// target: a dev
// database, a cache, a service in docker compose. Each connection is
// checked by policy (a net.connect effect, like a proxy connection) and
// logged as net.tcp. Once the session reads a secret, connections to
// targets off this machine are refused and open ones closed; loopback
// targets stay, since data written there does not leave the machine.
type forwarder struct {
	f    session.Forward
	gate *policy.Gate
	log  *effects.Log

	mu      sync.Mutex
	open    map[net.Conn]bool
	stopped bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func newForwarder(f session.Forward, gate *policy.Gate, log *effects.Log) *forwarder {
	ctx, cancel := context.WithCancel(context.Background())
	return &forwarder{f: f, gate: gate, log: log, open: map[net.Conn]bool{}, ctx: ctx, cancel: cancel}
}

func (fw *forwarder) target() string { return net.JoinHostPort(fw.f.Host, strconv.Itoa(fw.f.Port)) }

func (fw *forwarder) local() bool {
	if fw.f.Host == "localhost" {
		return true
	}
	ip := net.ParseIP(fw.f.Host)
	return ip != nil && ip.IsLoopback()
}

func (fw *forwarder) serve(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		fw.mu.Lock()
		if fw.stopped {
			fw.mu.Unlock()
			c.Close()
			continue
		}
		fw.wg.Add(1)
		fw.mu.Unlock()
		go func() { defer fw.wg.Done(); fw.handle(c) }()
	}
}

func (fw *forwarder) handle(c net.Conn) {
	defer c.Close()
	fw.mu.Lock()
	if fw.stopped {
		fw.mu.Unlock()
		return
	}
	fw.open[c] = true
	fw.mu.Unlock()
	defer func() { fw.mu.Lock(); delete(fw.open, c); fw.mu.Unlock() }()
	deny := func(reason string) {
		fw.log.Add(effects.Effect{Kind: "net.tcp", Target: fw.target(), Verdict: "deny", Reason: reason})
	}
	if fw.gate.Tainted() != "" && !fw.local() {
		deny("secret-taint")
		return
	}
	if d, _ := fw.gate.Check(policy.Input{Effect: models.Effect{Kind: "net.connect", Target: fw.f.Host, Detail: strconv.Itoa(fw.f.Port)}}); d.Verdict != policy.Allow {
		deny(d.Rule)
		return
	}
	up, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(fw.ctx, "tcp", fw.target())
	if err != nil {
		fw.log.Add(effects.Effect{Kind: "net.tcp", Target: fw.target(), Verdict: "allow", Reason: "unreachable: " + err.Error()})
		return
	}
	defer up.Close()
	fw.log.Add(effects.Effect{Kind: "net.tcp", Target: fw.target(), Verdict: "allow"})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// cut closes open connections to a target off this machine.
func (fw *forwarder) cut() {
	if fw.local() {
		return
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	for c := range fw.open {
		_ = c.Close()
		fw.log.Add(effects.Effect{Kind: "net.tcp", Target: fw.target(), Verdict: "cut", Reason: "secret-taint"})
	}
}

func (fw *forwarder) close() {
	fw.mu.Lock()
	fw.stopped = true
	fw.cancel()
	for c := range fw.open {
		c.Close()
	}
	fw.mu.Unlock()
	fw.wg.Wait()
}
