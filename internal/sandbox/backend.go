package sandbox

import (
	"fmt"
	"runtime"
	"slices"
)

// Egress values. Agent traffic goes through airbag's allowlist proxy; a
// run that leaves the Nix daemon's socket reachable (--nix-daemon) has a
// second path, the daemon's builds and substitutes, outside the proxy.
const (
	EgressProxy          = "allowlist-proxy"
	EgressProxyNixDaemon = "allowlist-proxy+nix-daemon"
)

// Backend describes the compiled execution boundary, not a successful probe
// or a security attestation. Policy, credential mediation and result import
// remain host responsibilities when another execution backend is added.
type Backend struct {
	Schema          int      `json:"schema"`
	Name            string   `json:"name"`
	Platform        string   `json:"platform"`
	Isolation       string   `json:"isolation"`
	Mechanism       string   `json:"mechanism"`
	WorkspaceBranch string   `json:"workspace_branch"`
	HomeBranch      bool     `json:"home_branch"`
	Egress          string   `json:"egress"`
	Readiness       string   `json:"readiness"`
	Limitations     []string `json:"limitations"`
}

func NativeBackend() Backend { return nativeBackend(runtime.GOOS) }

func nativeBackend(platform string) Backend {
	b := Backend{
		Schema: 1, Name: "native", Platform: platform, Isolation: "shared-kernel",
		Readiness: "not-probed", Egress: EgressProxy,
		Limitations: []string{
			"agent code shares the host kernel; kernel exploits are outside this boundary",
			"allowed network destinations can receive agent data and perform remote effects",
			"--nix-daemon: the Nix daemon's builds and substitutes reach the network outside the proxy; such a session records egress " + EgressProxyNixDaemon,
			"agent state passthroughs can persist without apply",
			"credential placeholders do not provide JIT issuance, token scope or TTL",
			"secret taint narrows egress; it is not a general automatic process kill switch",
		},
	}
	switch platform {
	case "linux":
		b.Mechanism, b.WorkspaceBranch, b.HomeBranch = "namespaces+overlayfs+seccomp", "overlayfs", true
	case "darwin":
		b.Mechanism, b.WorkspaceBranch = "seatbelt+workspace-clone", "clone"
		b.Limitations = append(b.Limitations, "macOS is a prototype; HOME has no branch")
	default:
		b.Isolation, b.Mechanism, b.Egress = "unsupported", "unsupported", "unsupported"
	}
	return b
}

// ForRun is b as a session with these hidden host paths runs it: one that
// leaves the Nix daemon's socket reachable does not keep egress in the
// proxy. A session that hides nothing (an older airbag's) is reported so.
// Only native execution sees the host's sockets; the optional runtimes
// mount none of them and refuse --nix-daemon.
func (b Backend) ForRun(hiddenHost []string) Backend {
	if b.Name == "native" && b.Egress == EgressProxy && !slices.Contains(hiddenHost, NixDaemonSocket) {
		b.Egress = EgressProxyNixDaemon
	}
	return b
}

// SelectBackend never substitutes native execution for an unavailable backend.
func SelectBackend(name, isolation string) (Backend, error) {
	b := NativeBackend()
	if name != "native" {
		if runtime.GOOS != "linux" || (name != "gvisor" && name != "microvm") {
			return Backend{}, fmt.Errorf("execution backend %q is unavailable on %s (no fallback)", name, runtime.GOOS)
		}
		b.Name, b.HomeBranch, b.WorkspaceBranch = name, false, "private-copy"
		b.Readiness = "experimental; runtime preflight required"
		b.Limitations = []string{
			"isolated profile requires --no-home; host HOME and agent state passthroughs are unavailable",
			"workspace secret files, explicit hide rules, TCP forwards and Nix daemon access are rejected",
			"noninteractive execution only; no terminal resize/job control",
			"command models remain shim-based; complete filesystem/process audit is unavailable",
			"credential placeholders have no JIT issuance or TTL; no automatic process kill switch",
			"trusted rootfs and runtime binaries are supplied by the operator; no image provenance verification",
		}
		if name == "gvisor" {
			b.Isolation, b.Mechanism = "application-kernel", "runsc-systrap+network-none+scoped-unix-sockets"
		} else {
			b.Isolation, b.Mechanism = "virtual-machine", "firecracker-kvm+no-nic+scoped-vsock"
			b.Limitations = append(b.Limitations, "Firecracker jailer and fleet resource management are not integrated")
		}
	}
	if b.Isolation == "unsupported" {
		return Backend{}, fmt.Errorf("native execution is unsupported on %s", b.Platform)
	}
	if err := b.Require(isolation); err != nil {
		return Backend{}, err
	}
	return b, nil
}

// Require uses named boundaries, not a claim that all VMs rank above every
// application kernel. "any" accepts the chosen boundary explicitly.
func (b Backend) Require(isolation string) error {
	switch isolation {
	case "any", "shared-kernel", "application-kernel", "virtual-machine":
	default:
		return fmt.Errorf("unknown isolation requirement %q; want any, shared-kernel, application-kernel or virtual-machine", isolation)
	}
	if isolation != "any" && b.Isolation != isolation {
		return fmt.Errorf("backend %s provides %s, but %s was required (no fallback)", b.Name, b.Isolation, isolation)
	}
	return nil
}
