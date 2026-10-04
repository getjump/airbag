// Package sandbox runs the agent in a branch of the machine: Linux
// namespaces and overlayfs (init.go, run.go), or on macOS a Seatbelt
// profile around a clone of the workspace (run_darwin.go). What both
// share is here.
package sandbox

import (
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/mirror"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/taint"
)

// InitArg is the hidden subcommand that runs inside the namespaces.
const InitArg = "__airbag_init"

// DefaultPassthrough: agent state that must survive a discarded branch
// (transcripts, logs, login refreshes). Paths are relative to $HOME.
// A trailing slash marks a directory, which airbag creates if missing.
var DefaultPassthrough = []string{
	".claude/projects/", ".claude/sessions/", ".claude/file-history/", ".claude/session-env/",
	".claude/shell-snapshots/", ".claude/todos/", ".claude/statsig/", ".claude/backups/",
	".claude/debug/", ".claude/ide/", ".claude/plans/",
	".claude/.credentials.json", ".claude.json",
	".codex/sessions/", ".codex/log/", ".codex/auth.json",
}

// DefaultHidden: credentials the agent never sees. Paths are relative
// to $HOME; a directory becomes an empty tmpfs, a file reads as empty.
var DefaultHidden = []string{
	".ssh", ".aws", ".gnupg", ".config/gh", ".config/gcloud", ".azure",
	".kube", ".docker", ".netrc", ".git-credentials", ".npmrc", ".pypirc",
	".config/hub", ".terraform.d/credentials.tfrc.json",
	// Decryption keys and decrypted secrets: sops and age keys,
	// sops-nix's runtime secrets, pass, Vault, rclone remotes, keyrings.
	".config/sops", ".config/sops-nix", ".config/age", ".password-store", ".vault-token",
	".config/rclone", ".local/share/keyrings", ".config/op",
}

// HostSockets: daemons whose sockets live outside /run, which the
// sandbox makes private. A unix socket path is reachable from any
// network namespace, and connecting needs no write access to the
// mount, so a read-only host does not stop it. Each would act for the
// agent outside the sandbox: Incus and LXD as root (for members of
// their admin group), the Nix daemon by building with network access
// outside the proxy (see --nix-daemon).
var HostSockets = []string{
	NixDaemonSocket,
	"/var/lib/incus/unix.socket", "/var/lib/incus/unix.socket.user",
	"/var/lib/lxd/unix.socket", "/var/snap/lxd/common/lxd/unix.socket",
	"/var/snap/lxd/common/lxd/unix.socket.user",
}

const NixDaemonSocket = "/nix/var/nix/daemon-socket"

// restoreLabels replays the session's effect log into the gate, so a
// resumed session keeps what it learned before: a secret read in an
// earlier run still narrows egress in this one.
func restoreLabels(gate *policy.Gate, s *session.Session) {
	prev, err := effects.Read(s.EffectsPath())
	if err != nil {
		return
	}
	for _, e := range prev {
		switch {
		case e.Kind == "secret.read":
			gate.Mark(taint.Secret, e.Target)
		case e.Kind == "label" && e.Verdict == string(taint.Untrusted):
			gate.Mark(taint.Untrusted, e.Target)
		}
	}
}

func agentEnvFor(s *session.Session, proxyAddr, binDir, runtimeDir string) []string {
	drop := map[string]bool{
		"SSH_AUTH_SOCK": true, "SSH_AGENT_PID": true, "GPG_AGENT_INFO": true,
		"DBUS_SESSION_BUS_ADDRESS": true, "DISPLAY": true, "WAYLAND_DISPLAY": true,
		"XAUTHORITY": true, "DOCKER_HOST": true, "KRB5CCNAME": true,
		"ALL_PROXY": true, "all_proxy": true,
	}
	set := map[string]string{
		"HTTPS_PROXY": "http://" + proxyAddr, "https_proxy": "http://" + proxyAddr,
		"HTTP_PROXY": "http://" + proxyAddr, "http_proxy": "http://" + proxyAddr,
		"NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1",
		"XDG_RUNTIME_DIR":  runtimeDir,
		"AIRBAG_SESSION":   s.ID,
		"AIRBAG_WORKSPACE": s.Workspace,
		// Claude Code runs its Bash tool through this shell.
		"CLAUDE_CODE_SHELL": binDir + "/bash",
	}
	var env []string
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if drop[k] || (Credential(k, v) && !contains(s.PassEnv, k)) {
			continue
		}
		if _, ok := set[k]; ok {
			continue
		}
		if k == "PATH" {
			v = binDir + ":" + v
		}
		env = append(env, k+"="+proxyVar(k, v, proxyAddr))
	}
	for k, v := range set {
		env = append(env, k+"="+v)
	}
	// Package managers go through the mirror unless the user chose a
	// registry of their own.
	for k, v := range mirror.Env {
		if os.Getenv(k) == "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// agentAuth: credentials the agents themselves need to reach their API.
var agentAuth = map[string]bool{
	"ANTHROPIC_API_KEY": true, "ANTHROPIC_AUTH_TOKEN": true, "CLAUDE_CODE_OAUTH_TOKEN": true,
	"OPENAI_API_KEY": true, "CODEX_API_KEY": true,
}

// Credential reports whether an environment variable looks like a
// secret the agent should not get (unless passed with --pass-env).
func Credential(name, value string) bool {
	if agentAuth[name] || len(value) < 8 || strings.Trim(value, "0123456789") == "" {
		return false // agent keys, short values and numbers (MAX_*_TOKENS)
	}
	if strings.HasSuffix(name, "_FILE") || strings.HasPrefix(value, "/") {
		return false // a path; the file itself is what matters
	}
	u := strings.ToUpper(name)
	if strings.Contains(u, "PROXY") {
		return false
	}
	for _, w := range []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "PRIVATE_KEY", "CREDENTIAL", "ACCESS_KEY"} {
		if strings.Contains(u, w) {
			return true
		}
	}
	return false
}

// proxyVar points tool-specific proxy settings (npm_config_proxy,
// CLOUDSDK_PROXY_PORT, ...) at airbag's proxy: the host's proxy is not
// reachable from the sandbox's network.
func proxyVar(name, v, proxyAddr string) string {
	u := strings.ToUpper(name)
	if !strings.Contains(u, "PROXY") || strings.Contains(u, "NO_PROXY") || strings.Contains(u, "NOPROXY") {
		return v
	}
	switch {
	case strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://"):
		return "http://" + proxyAddr
	case strings.HasSuffix(u, "PROXY_PORT"):
		_, port, _ := strings.Cut(proxyAddr, ":")
		return port
	case strings.HasSuffix(u, "PROXY_ADDRESS") || strings.HasSuffix(u, "PROXY_HOST"):
		host, _, _ := strings.Cut(proxyAddr, ":")
		return host
	}
	return v
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func lookPath(name string, env []string) (string, error) {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			for _, dir := range filepath.SplitList(v) {
				p := filepath.Join(dir, name)
				if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
					return p, nil
				}
			}
		}
	}
	return "", os.ErrNotExist
}

// swallow catches signals and drops them. Unlike signal.Ignore, caught
// signals are reset to their default in child processes.
func swallow(sigs ...os.Signal) {
	ch := make(chan os.Signal, 8)
	signal.Notify(ch, sigs...)
	go func() {
		for range ch {
		}
	}()
}
