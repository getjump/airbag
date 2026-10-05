package sandbox

import (
	"fmt"
	"runtime"
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
		Readiness: "not-probed", Egress: "allowlist-proxy",
		Limitations: []string{
			"agent code shares the host kernel; kernel exploits are outside this boundary",
			"allowed network destinations can receive agent data and perform remote effects",
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

// SelectBackend never substitutes native execution for an unavailable backend.
func SelectBackend(name, isolation string) (Backend, error) {
	b := NativeBackend()
	if name != "native" {
		return Backend{}, fmt.Errorf("execution backend %q is unavailable in this build; only native is implemented (no fallback)", name)
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
