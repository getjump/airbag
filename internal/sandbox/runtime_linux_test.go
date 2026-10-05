//go:build linux

package sandbox

import "testing"

// runsc, Firecracker and their tools get PATH and nothing else of airbag's
// environment.
func TestProviderEnvIsMinimal(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "benign-canary-0123456789")
	t.Setenv("PATH", "/usr/bin:/bin")
	if env := providerEnv(); len(env) != 1 || env[0] != "PATH=/usr/bin:/bin" {
		t.Fatalf("provider environment: %q", env)
	}
}
