package sandbox

import (
	"slices"
	"strings"
	"testing"
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

func TestNixDaemonEgressIsReported(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		b := nativeBackend(platform)
		if b.Egress != EgressProxy || !slices.ContainsFunc(b.Limitations, func(l string) bool { return strings.Contains(l, "--nix-daemon") }) {
			t.Fatalf("%s: the compiled report does not mention --nix-daemon egress: %+v", platform, b)
		}
		hidden := append([]string{"/elsewhere"}, HostSockets...)
		if got := b.ForRun(hidden).Egress; got != EgressProxy {
			t.Fatalf("%s: a run hiding the Nix socket reports %s", platform, got)
		}
		open := slices.DeleteFunc(slices.Clone(hidden), func(p string) bool { return p == NixDaemonSocket })
		for _, h := range [][]string{open, nil} {
			if got := b.ForRun(h).Egress; got != EgressProxyNixDaemon {
				t.Fatalf("%s: a run reaching the Nix daemon (%v) reports %s", platform, h, got)
			}
		}
		if b.Egress != EgressProxy {
			t.Fatal("ForRun changed the compiled report")
		}
	}
	if got := nativeBackend("plan9").ForRun(nil).Egress; got != "unsupported" {
		t.Fatalf("unsupported platform reports %s", got)
	}
}
