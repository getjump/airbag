package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

// A wildcard entry must match only on a dot boundary: *.example.com
// covers a.example.com, never example.com or notexample.com. An exact
// entry matches only that host. Case and a trailing dot do not matter.
func FuzzAllowlist(f *testing.F) {
	for _, h := range []string{"example.com", "a.example.com", "notexample.com", "A.Example.com.", "x.a.example.com", ".example.com", "api.github.com", ".EXAmple.Com[", "[a.example.com]", "[api.github.com]"} {
		f.Add(h)
	}
	f.Fuzz(func(t *testing.T, host string) {
		norm := strings.ToLower(strings.TrimSuffix(host, "."))
		if strings.ContainsAny(host, " \t\r\n") {
			return // a host is one token; Fields-level garbage is not a host
		}
		gotW := Allowlist{"*.example.com"}.Allows(host)
		wantW := strings.HasSuffix(norm, ".example.com")
		if gotW != wantW {
			t.Fatalf("wildcard Allows(%q) = %v, want %v", host, gotW, wantW)
		}
		gotE := Allowlist{"api.github.com"}.Allows(host)
		if wantE := norm == "api.github.com"; gotE != wantE {
			t.Fatalf("exact Allows(%q) = %v, want %v", host, gotE, wantE)
		}
	})
}

// Any address the standard library calls loopback, unspecified,
// link-local or multicast must be forbidden; the proxy may forbid more
// (the host's own addresses), never fewer.
func FuzzForbidden(f *testing.F) {
	f.Add([]byte{127, 0, 0, 1})
	f.Add([]byte{169, 254, 0, 1})
	f.Add([]byte{8, 8, 8, 8})
	f.Add([]byte{0, 0, 0, 0})
	f.Add(make([]byte, 16))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var a netip.Addr
		switch len(raw) {
		case 4:
			a = netip.AddrFrom4([4]byte(raw))
		case 16:
			a = netip.AddrFrom16([16]byte(raw))
		default:
			return
		}
		u := a.Unmap()
		if nat64.Contains(u) {
			b := u.As16()
			u = netip.AddrFrom4([4]byte(b[12:]))
		}
		must := u.IsLoopback() || u.IsUnspecified() || thisNetwork.Contains(u) ||
			u.IsLinkLocalUnicast() || u.IsLinkLocalMulticast() || u.IsMulticast() || u == broadcast
		if must && forbidden(a) == "" {
			t.Fatalf("forbidden(%v) allowed a local/special address", a)
		}
	})
}

// The proxy runs in the host's network namespace: an allowed name that
// resolves to one of this machine's own addresses must be refused,
// not only loopback.
func TestForbiddenOwnAddress(t *testing.T) {
	own, err := net.InterfaceAddrs()
	if err != nil {
		t.Skip(err)
	}
	tested := 0
	for _, o := range own {
		p, err := netip.ParsePrefix(o.String())
		if err != nil || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
			continue // those are refused for another reason; test the own-address rule alone
		}
		tested++
		if why := forbidden(p.Addr()); why != "this machine's own address" {
			t.Errorf("forbidden(%v) = %q, want this machine's own address", p.Addr(), why)
		}
		if why := forbidden(netip.AddrFrom16(p.Addr().As16())); p.Addr().Is4() && why == "" {
			t.Errorf("own address %v allowed in its IPv4-mapped form", p.Addr())
		}
	}
	if tested == 0 {
		t.Skip("no non-loopback interface address here")
	}
}

// The mirror answers plain requests to airbag.mirror only: a CONNECT
// to that name is not the mirror (and is not on the allowlist), and no
// other host reaches the mirror handler.
func TestMirrorRouting(t *testing.T) {
	log, _ := newLog(t)
	hit := 0
	p := New(Allowlist{"api.anthropic.com"}, log)
	p.Mirror = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit++ })
	get := func(method, host string) int {
		rec := httptest.NewRecorder()
		u := &url.URL{Scheme: "http", Host: host, Path: "/x"}
		if method == http.MethodConnect {
			u = &url.URL{Host: host}
		}
		p.ServeHTTP(rec, &http.Request{Method: method, Host: host, URL: u, Header: http.Header{}})
		return rec.Code
	}
	get(http.MethodGet, "airbag.mirror")
	if hit != 1 {
		t.Fatalf("GET airbag.mirror did not reach the mirror (hits %d)", hit)
	}
	if code := get(http.MethodConnect, "airbag.mirror:443"); hit != 1 || code != http.StatusForbidden {
		t.Fatalf("CONNECT airbag.mirror: hits %d code %d, want no hit and 403", hit, code)
	}
	if code := get(http.MethodGet, "evil.example"); hit != 1 || code != http.StatusForbidden {
		t.Fatalf("another host reached the mirror or was allowed: hits %d code %d", hit, code)
	}
}
