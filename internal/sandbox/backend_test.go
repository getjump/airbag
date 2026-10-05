package sandbox

import (
	"slices"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

func TestNativeBoundaries(t *testing.T) {
	linux, mac := nativeBackend("linux"), nativeBackend("darwin")
	if linux.Isolation != "shared-kernel" || mac.Isolation != "shared-kernel" {
		t.Fatal("native must not claim a separate application or guest kernel")
	}
	if !linux.HomeBranch || mac.HomeBranch || mac.WorkspaceBranch != "clone" {
		t.Fatal("platform filesystem guarantees differ")
	}
	for _, b := range []Backend{linux, mac} {
		for _, required := range []string{"application-kernel", "virtual-machine", "typo"} {
			if b.Require(required) == nil {
				t.Fatalf("%s accepted %s", b.Platform, required)
			}
		}
	}
}

// Egress is classified from what each platform opens: on Linux the Nix
// daemon's socket when the session does not hide it and every tcp://
// forward, on macOS only forwards to this machine, since its profile
// allows no Nix socket.
func TestEgressIsReportedAsThePlatformOpensIt(t *testing.T) {
	hidden := append([]string{"/elsewhere"}, HostSockets...)
	open := slices.DeleteFunc(slices.Clone(hidden), func(p string) bool { return p == NixDaemonSocket })
	remote := []session.Forward{{Host: "db.internal", Port: 5432}}
	local := []session.Forward{{Host: "127.0.0.1", Port: 5432}}
	for _, c := range []struct {
		platform string
		hidden   []string
		forwards []session.Forward
		want     string
	}{
		{"linux", hidden, nil, EgressProxy},
		{"linux", open, nil, EgressProxyNixDaemon},
		{"linux", nil, nil, EgressProxyNixDaemon}, // an older session that hides nothing
		{"linux", hidden, remote, EgressProxyForward},
		{"linux", hidden, local, EgressProxyForward},
		{"linux", open, remote, EgressProxyNixDaemon + "+tcp-forward"},
		{"darwin", hidden, nil, EgressProxy},
		{"darwin", open, nil, EgressProxy},
		{"darwin", nil, nil, EgressProxy},
		{"darwin", hidden, remote, EgressProxy}, // the profile does not let it
		{"darwin", open, local, EgressProxyForward},
		{"plan9", nil, local, "unsupported"},
	} {
		b := nativeBackend(c.platform)
		if got := b.ForRun(c.hidden, c.forwards).Egress; got != c.want {
			t.Errorf("%s, hidden %v, forwards %v: egress %s, want %s", c.platform, c.hidden, c.forwards, got, c.want)
		}
		if c.platform != "plan9" && b.Egress != EgressProxy {
			t.Fatalf("%s: the compiled report says %s", c.platform, b.Egress)
		}
	}
	mentions := func(b Backend, flag string) bool {
		return slices.ContainsFunc(b.Limitations, func(l string) bool { return strings.Contains(l, flag) })
	}
	linux, mac := nativeBackend("linux"), nativeBackend("darwin")
	if !mentions(linux, "--nix-daemon") || !mentions(linux, "tcp://") || !mentions(mac, "tcp://") {
		t.Fatalf("the compiled reports do not name the paths around the proxy: %q / %q", linux.Limitations, mac.Limitations)
	}
	if mentions(mac, "--nix-daemon") {
		t.Fatal("macOS claims --nix-daemon egress its profile does not allow")
	}
}

// The forwards macOS's profile opens are the ones ForRun counts there.
func TestMacForwardMatchesProfile(t *testing.T) {
	for _, f := range []session.Forward{{Host: "localhost", Port: 1}, {Host: "127.0.0.1", Port: 2}, {Host: "::1", Port: 3}, {Host: "db.internal", Port: 4}, {Host: "10.0.0.1", Port: 5}} {
		s := &session.Session{Meta: session.Meta{ID: "s-test", Home: t.TempDir(), Forwards: []session.Forward{f}}, Dir: t.TempDir()}
		p, err := macProfile(s, 9999, t.TempDir(), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if got := slices.Contains(p.Ports, f.Port); got != macForward(f) {
			t.Fatalf("%+v: profile opens it %v, macForward says %v", f, got, macForward(f))
		}
	}
}
