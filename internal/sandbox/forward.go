//go:build linux

package sandbox

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/models"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/proxy"
	"github.com/getjump/airbag/internal/session"
)

// forwarder relays the agent's connections to a tcp:// target: a dev
// database, a cache, a service in docker compose. Each connection is
// checked by policy (a net.connect effect, like a proxy connection) and
// logged as net.tcp. Once the session reads a secret, connections to
// targets off this machine are refused and open ones closed; loopback
// targets stay, since data written there does not leave the machine.
//
// The relay runs on the host side, so what the agent can hold open is
// bounded: a connection closes after idle with no byte either way, or
// once one side has finished sending and the other has been quiet for
// drain (proxy.ForwardIdle, proxy.Drain), and at most max are open (or
// being dialled) at once.
type forwarder struct {
	f    session.Forward
	gate *policy.Gate
	log  *effects.Log

	idle, drain time.Duration
	max         int

	mu   sync.Mutex
	n    int // connections admitted
	open map[net.Conn]bool
}

// maxForwardConns caps the connections relayed to one tcp:// target at
// once: well above a database client's pool.
const maxForwardConns = 256

func newForwarder(f session.Forward, gate *policy.Gate, log *effects.Log) *forwarder {
	return &forwarder{f: f, gate: gate, log: log, idle: proxy.ForwardIdle, drain: proxy.Drain, max: maxForwardConns, open: map[net.Conn]bool{}}
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
		go fw.handle(c)
	}
}

func (fw *forwarder) handle(c net.Conn) {
	defer c.Close()
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
	fw.mu.Lock()
	if fw.max > 0 && fw.n >= fw.max {
		fw.mu.Unlock()
		deny("too many open connections")
		return
	}
	fw.n++
	fw.mu.Unlock()
	defer func() {
		fw.mu.Lock()
		fw.n--
		fw.mu.Unlock()
	}()
	up, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(context.Background(), "tcp", fw.target())
	if err != nil {
		fw.log.Add(effects.Effect{Kind: "net.tcp", Target: fw.target(), Verdict: "allow", Reason: "unreachable: " + err.Error()})
		return
	}
	defer up.Close()
	fw.mu.Lock()
	fw.open[c] = true
	fw.mu.Unlock()
	defer func() {
		fw.mu.Lock()
		delete(fw.open, c)
		fw.mu.Unlock()
	}()
	// A secret read while this connection was dialled: cut has run
	// already and did not see it.
	if fw.gate.Tainted() != "" && !fw.local() {
		deny("secret-taint")
		return
	}
	fw.log.Add(effects.Effect{Kind: "net.tcp", Target: fw.target(), Verdict: "allow"})
	proxy.Relay(c, up, fw.idle, fw.drain)
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
