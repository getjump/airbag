package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// The proxy runs in the host's network namespace, so an allowed name
// that resolves to the host itself, a cloud metadata service or another
// local-only address would reach what the sandbox's own network cannot.
// The address is checked in the dialer's Control hook: the address
// checked is the address connected to, with no second lookup that a
// rebinding DNS server could answer differently.
//
// Private ranges (10/8, 192.168/16, fc00::/7) stay reachable: company
// services the user allows by name live there. The host's own
// addresses on those ranges do not.

var (
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	nat64       = netip.MustParsePrefix("64:ff9b::/96")
	broadcast   = netip.AddrFrom4([4]byte{255, 255, 255, 255})
	// Metadata services outside link-local: AWS over IPv6, Alibaba Cloud.
	metadata = []netip.Addr{netip.MustParseAddr("fd00:ec2::254"), netip.MustParseAddr("100.100.100.200")}
)

// forbidden says why the proxy must not connect to a, or "".
func forbidden(a netip.Addr) string {
	a = a.Unmap()
	if nat64.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte(b[12:]))
	}
	switch {
	case a.IsLoopback():
		return "loopback"
	case a.IsUnspecified() || thisNetwork.Contains(a):
		return "this host"
	case a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast():
		return "link-local, where cloud metadata services live"
	case a.IsMulticast() || a == broadcast:
		return "multicast or broadcast"
	}
	for _, m := range metadata {
		if a == m {
			return "a cloud metadata service"
		}
	}
	if own, err := net.InterfaceAddrs(); err == nil {
		for _, o := range own {
			if p, err := netip.ParsePrefix(o.String()); err == nil && p.Addr().Unmap() == a {
				return "this machine's own address"
			}
		}
	}
	return ""
}

type blockedAddr struct{ addr, why string }

func (e *blockedAddr) Error() string {
	return fmt.Sprintf("resolves to %s (%s); airbag's proxy does not connect there", e.addr, e.why)
}

// dialer connects to hostport. With check, every address it is about
// to connect to must pass forbidden.
func (p *Proxy) dialer(check bool) *net.Dialer {
	d := &net.Dialer{Timeout: 15 * time.Second}
	if check {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			if why := p.forbid(ap.Addr()); why != "" {
				return &blockedAddr{addr: ap.Addr().Unmap().String(), why: why}
			}
			return nil
		}
	}
	return d
}

func (p *Proxy) dialContext(check bool) func(context.Context, string, string) (net.Conn, error) {
	return p.dialer(check).DialContext
}

// webPorts are reachable on every allowed host; another port needs an
// allowlist entry that names it ("host:8443") or "host:*".
var webPorts = []string{"80", "443"}

// AllowsPort reports whether host may be reached on port.
func (a Allowlist) AllowsPort(host, port string) bool {
	for _, w := range webPorts {
		if port == w && a.Allows(host) {
			return true
		}
	}
	for _, e := range a {
		h, ep, err := net.SplitHostPort(e)
		if err == nil && (ep == port || ep == "*") && (Allowlist{h}).Allows(host) {
			return true
		}
	}
	return false
}

// explicitIP reports whether host is an IP literal the allowlist names
// itself: the user asked for that address, so it is not checked.
func (a Allowlist) explicitIP(host string) bool {
	if _, err := netip.ParseAddr(host); err != nil {
		return false
	}
	for _, e := range a {
		if h, _, err := net.SplitHostPort(e); err == nil {
			e = h
		}
		if strings.EqualFold(strings.Trim(e, "[]"), host) {
			return true
		}
	}
	return false
}
