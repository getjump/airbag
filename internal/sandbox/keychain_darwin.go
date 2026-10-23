//go:build darwin

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"
)

// keychainTimeout: security(1) may wait on a Keychain prompt the user never
// sees from a terminal; the run goes on without the login instead.
const keychainTimeout = 10 * time.Second

// readKeychain reads a generic password of the current user. It runs in
// airbag's own process, outside the profile: the agent still cannot reach
// the Keychain.
func readKeychain(service string) ([]byte, error) {
	account := os.Getenv("USER")
	if u, err := user.Current(); err == nil {
		account = u.Username
	}
	ctx, cancel := context.WithTimeout(context.Background(), keychainTimeout)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-s", service, "-a", account, "-w") //nolint:gosec // a fixed binary; the service is from agents.HostLogins and the account from the OS, passed as arguments, not through a shell
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, errors.New("security(1) timed out, perhaps waiting for a Keychain prompt")
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}
	return bytes.TrimSpace(out), nil
}
