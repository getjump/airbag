package sandbox

import (
	"fmt"
	"runtime"
	"slices"

	"github.com/getjump/airbag/internal/session"
)

// Egress values. Agent traffic goes through airbag's allowlist proxy. A
// session can have paths around it, named after "+" in this order: the
// Nix daemon (--nix-daemon on Linux), whose builds and substitutes reach
// the network, and tcp:// forwards, connections to HOST:PORT that are not
// proxied (on Linux airbag dials them from the host).
const (
	EgressProxy          = "allowlist-proxy"
	EgressProxyNixDaemon = EgressProxy + egressNixDaemon
	EgressProxyForward   = EgressProxy + egressForward

	egressNixDaemon = "+nix-daemon"
	egressForward   = "+tcp-forward"
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

// sharedLimitations hold for every backend: they come from the host's
// policy, proxy and credentials, which all backends share.
var sharedLimitations = []string{
	"allowed network destinations can receive agent data and perform remote effects",
	"credential placeholders do not provide JIT issuance, token scope or TTL",
	"secret taint narrows egress; it is not a general automatic process kill switch",
}

func NativeBackend() Backend { return nativeBackend(runtime.GOOS) }

func nativeBackend(platform string) Backend {
	b := Backend{
		Schema: 1, Name: "native", Platform: platform, Isolation: "shared-kernel",
		Readiness: "not-probed", Egress: EgressProxy,
		Limitations: append([]string{
			"agent code shares the host kernel; kernel exploits are outside this boundary",
			"agent state passthroughs can persist without apply",
		}, sharedLimitations...),
	}
	switch platform {
	case "linux":
		b.Mechanism, b.WorkspaceBranch, b.HomeBranch = "namespaces+overlayfs+seccomp", "overlayfs", true
		b.Limitations = append(b.Limitations,
			"--nix-daemon: the Nix daemon's builds and substitutes reach the network outside the proxy; such a session records egress "+EgressProxyNixDaemon,
			"--allow tcp://HOST:PORT: airbag connects to HOST:PORT from the host for the agent, outside the proxy (each connection is policy-checked and logged); such a session records egress "+EgressProxyForward)
	case "darwin":
		b.Mechanism, b.WorkspaceBranch = "seatbelt+workspace-clone", "clone"
		b.Limitations = append(b.Limitations, "macOS is a prototype; HOME has no branch",
			"--allow tcp://localhost:PORT: the agent connects to that port directly, outside the proxy and unchecked; such a session records egress "+EgressProxyForward)
	default:
		b.Isolation, b.Mechanism, b.Egress = "unsupported", "unsupported", "unsupported"
	}
	return b
}

// ForRun is b as a session with these hidden host paths and tcp://
// forwards runs it, from what each platform really opens. On Linux a Nix
// daemon socket the session does not hide is reachable (a session that
// hides nothing, an older airbag's, is reported so), and every forward is
// dialed from the host. macOS's profile allows no Nix socket whatever
// HiddenHost says, and only the forwards to this machine (macForward).
// The optional runtimes mount no host socket and refuse --nix-daemon and
// forwards, so their egress is the proxy's.
func (b Backend) ForRun(hiddenHost []string, forwards []session.Forward) Backend {
	if b.Name != "native" || b.Egress != EgressProxy {
		return b
	}
	if b.Platform == "linux" && !slices.Contains(hiddenHost, NixDaemonSocket) {
		b.Egress += egressNixDaemon
	}
	if slices.ContainsFunc(forwards, func(f session.Forward) bool { return b.Platform == "linux" || macForward(f) }) {
		b.Egress += egressForward
	}
	return b
}

// macForward reports whether macOS's profile lets the agent reach f: a
// port on this machine, which it connects to directly.
func macForward(f session.Forward) bool {
	return f.Host == "localhost" || f.Host == "127.0.0.1" || f.Host == "::1"
}

// UsesRuntimePolicies reports whether s asks for a runtime policy
// option, which only the native sandbox runs.
func UsesRuntimePolicies(s *session.Session) bool {
	return s.FilePolicy || s.ExecPolicy || s.RuntimeProfile || s.FileCache != "" && s.FileCache != "off" || s.RuntimeAudit == "buffered"
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
		b.Limitations = append([]string{
			"isolated profile requires --no-home; host HOME and agent state passthroughs are unavailable",
			"workspace secret files, explicit hide rules, TCP forwards and Nix daemon access are rejected",
			"noninteractive execution only; no terminal resize/job control",
			"command models remain shim-based; complete filesystem/process audit is unavailable",
			"trusted rootfs and runtime binaries are supplied by the operator; no image provenance verification",
		}, sharedLimitations...)
		if name == "gvisor" {
			b.Isolation, b.Mechanism = "application-kernel", "runsc-systrap+network-none+scoped-unix-sockets"
			b.Limitations = append(b.Limitations,
				"run as root, runsc is rootful: the sandbox's uid 0 is the host's root for its file access, and the branch's files are owned by root")
		} else {
			b.Isolation, b.Mechanism = "virtual-machine", "firecracker-kvm+no-nic+scoped-vsock"
			b.Limitations = append(b.Limitations,
				"Firecracker runs without its jailer: a VMM escape runs as the invoking user, with their HOME, credentials and unfiltered network, and no chroot, cgroup or uid drop (Firecracker's own seccomp filters still apply)",
				"fleet resource management is not integrated")
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
