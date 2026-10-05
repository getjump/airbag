//go:build linux

package sandbox

import (
	"net"
	"time"

	"github.com/getjump/airbag/internal/control"
	"github.com/getjump/airbag/internal/netcap"
	"github.com/getjump/airbag/internal/proxy"
)

// relayLimits bound a relay between the guest and a host server: at most
// max pairs open at once, the most the server behind accepts, and each
// pair closed by proxy.Relay once idle, or drained after one side ends.
type relayLimits struct {
	max         int
	idle, drain time.Duration
}

// The relays to the proxy and the control socket hold no more than those
// accept (Proxy.Serve caps its connections at twice MaxFlows). Idle is
// the longest idle bound behind them, so a relay never cuts what the
// server would keep open.
var (
	proxyRelay   = relayLimits{max: 2 * proxy.MaxFlows, idle: proxy.TunnelIdle, drain: proxy.Drain}
	controlRelay = relayLimits{max: control.MaxConns, idle: proxy.TunnelIdle, drain: proxy.Drain}
)

// serveRelay relays each connection l accepts to one that dial opens,
// within lim. A pair past the cap is closed at once.
func serveRelay(l net.Listener, lim relayLimits, dial func() (net.Conn, error)) {
	l = netcap.Limit(l, lim.max)
	for {
		client, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			target, err := dial()
			if err != nil {
				_ = client.Close()
				return
			}
			proxy.Relay(client, target, lim.idle, lim.drain)
		}()
	}
}
