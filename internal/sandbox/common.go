// Package sandbox runs the agent in a branch of the machine: Linux
// namespaces and overlayfs (init.go, run.go), or on macOS a Seatbelt
// profile around a clone of the workspace (run_darwin.go). What both
// share is here.
package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/mirror"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/taint"
)

// InitArg is the hidden subcommand that runs inside the namespaces.
const InitArg = "__airbag_init"

// DefaultPassthrough: the agent state that bypasses the branch because
// it must survive a discard for the user's own workflow and the agent
// CLI never executes, loads as config, or restores it into other files.
// Everything else agents keep in $HOME goes through the branch, so it is
// shown in review and dropped on discard. Paths are relative to $HOME; a
// trailing slash marks a directory, which airbag creates if missing.
//
// This is the fixed part. The current workspace's transcript directory
// also passes through, but its path depends on the working directory, so
// ClaudeProjectState computes it per session (and keeps its memory/ in
// the branch). The passthrough stored on a session is the two combined.
//
//   - .claude/.credentials.json, .codex/auth.json: the login, so a
//     discard does not log the user out.
//   - .codex/sessions/, .codex/log/: Codex transcripts for resume. Codex
//     keys sessions by date (sessions/<year>/<month>/…), not by project,
//     so unlike Claude Code's they cannot be narrowed to this workspace;
//     a discard keeps every project's Codex transcripts (docs/macos.md).
//
// What used to pass through and now goes through the branch: the whole
// .claude/projects/ tree (only the current workspace's dir passes now),
// .claude/sessions/, file-history/, session-env/, shell-snapshots/,
// todos/, statsig/, backups/, debug/, ide/, plans/, and .claude.json
// (see agentconfig.go for its key-level write-back).
var DefaultPassthrough = []string{
	".claude/.credentials.json",
	".codex/sessions/", ".codex/log/", ".codex/auth.json",
}

// ClaudeProjectSlug is how Claude Code names a project's directory under
// ~/.claude/projects: the absolute path with every character that is not
// an ASCII letter or digit turned into "-" (so /home/me/my_proj becomes
// -home-me-my-proj; Claude Code 2.1.x, as its docs describe). Claude
// Code hashes names longer than maxSlug; airbag does not mirror the
// hash, so such a directory is not passed through: it stays in the
// branch, the safe side (docs/macos.md).
func ClaudeProjectSlug(dir string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, dir)
}

const maxSlug = 200

// NarrowPassthrough drops what a session stored before the passthrough
// was narrowed: a session created by an older airbag passed ~/.claude.json
// and all of ~/.claude/projects/ (and more) through, and resuming it must
// not keep that. What stays is today's DefaultPassthrough and the
// per-project transcript directories, each with its memory/ hole.
func NarrowPassthrough(s *session.Session) {
	pass := append([]string{}, DefaultPassthrough...)
	var holes []string
	for _, p := range s.Passthrough {
		if projectDir(p) {
			pass = appendNew(pass, p)
			holes = appendNew(holes, p+"memory")
		}
	}
	s.Passthrough, s.BranchHoles = pass, holes
}

// projectDir reports whether p is one project's directory,
// ".claude/projects/<slug>/", as ClaudeProjectState makes them.
func projectDir(p string) bool {
	slug, ok := strings.CutPrefix(p, ".claude/projects/")
	if !ok || !strings.HasSuffix(slug, "/") {
		return false
	}
	slug = strings.TrimSuffix(slug, "/")
	return slug != "" && slug != "." && slug != ".." && !strings.Contains(slug, "/")
}

// AddClaudeProjectState merges the transcript passthrough and memory
// holes for cwd (and the workspace root) into the session's, without
// duplicates. A resumed session may run from another directory of the
// same repository, whose transcript directory must pass through too.
func AddClaudeProjectState(s *session.Session, cwd string) {
	pass, holes := ClaudeProjectState(cwd, s.Workspace)
	s.Passthrough = appendNew(s.Passthrough, pass...)
	s.BranchHoles = appendNew(s.BranchHoles, holes...)
}

func appendNew(list []string, add ...string) []string {
	for _, a := range add {
		if !slices.Contains(list, a) {
			list = append(list, a)
		}
	}
	return list
}

// ClaudeProjectState returns, for the current workspace, the transcript
// directories that pass through to the real $HOME (so a resumed session
// keeps the conversation across a discard) and the memory/ directories
// inside them that stay in the branch. Claude Code writes transcripts
// under the slug of the working directory and auto-memory under the slug
// of the git root, so both are covered when they differ. memory/ holds
// instructions loaded into later sessions, so review shows it and a
// discard drops it, like any branch change.
//
// cwd and root are absolute paths; root is the git top-level (or "").
func ClaudeProjectState(cwd, root string) (pass, holes []string) {
	seen := map[string]bool{}
	// Claude Code names a directory by the physical path (its cwd is
	// resolved), while airbag may have been started from a path through a
	// symlink: both spellings are covered.
	dirs := []string{cwd, root}
	for _, d := range []string{cwd, root} {
		if d == "" {
			continue
		}
		if r, err := filepath.EvalSymlinks(d); err == nil && r != d {
			dirs = append(dirs, r)
		}
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		slug := ClaudeProjectSlug(d)
		if len(slug) > maxSlug {
			continue // Claude Code hashes it; see ClaudeProjectSlug
		}
		base := ".claude/projects/" + slug + "/"
		if seen[base] {
			continue
		}
		seen[base] = true
		pass = append(pass, base)
		holes = append(holes, base+"memory")
	}
	return pass, holes
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

func agentEnvFor(s *session.Session, proxyAddr, binDir, runtimeDir string, extra map[string]string) []string {
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
	for k, v := range extra {
		set[k] = v
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

// MacHidden: credentials a Mac keeps in its home besides DefaultHidden,
// relative to the home: keychains, sops and age keys, browser profiles
// (cookies are logins), password managers.
var MacHidden = []string{
	"Library/Keychains", "Library/Application Support/sops", "Library/Cookies",
	"Library/Application Support/Google/Chrome", "Library/Application Support/Firefox",
	"Library/Application Support/BraveSoftware", "Library/Safari",
	"Library/Group Containers/2BUA8C4S2C.com.1password",
}

// MacHomeRoots: where a Linux VM on a Mac shows the Mac's homes: Lima
// mounts them at their own path, OrbStack under /mnt/mac.
var MacHomeRoots = []string{"/Users", "/mnt/mac/Users"}

// MacHomesHidden lists the credential paths of every Mac home visible
// under roots, for a sandbox that runs in a VM on that Mac: the VM's
// own $HOME is hidden by DefaultHidden, the Mac's would not be.
func MacHomesHidden(roots []string) []string {
	var out []string
	for _, root := range roots {
		es, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range es {
			if !e.IsDir() || e.Name() == "Shared" || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			home := filepath.Join(root, e.Name())
			for _, h := range DefaultHidden {
				out = append(out, filepath.Join(home, h))
			}
			for _, h := range MacHidden {
				out = append(out, filepath.Join(home, h))
			}
		}
	}
	return out
}

// shimNames are the programs airbag stands in front of in the agent's
// PATH: git for the push outbox, the shells for command models, and
// the programs `defer:` entries name.
func shimNames(s *session.Session) []string {
	names := []string{"git", "bash", "sh"}
	for _, n := range s.Deferred {
		if _, err := policy.ParsePattern(n); err == nil && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return names
}

// noSymlinkSoFar is noSymlink for the components of rel that exist: a
// path about to be created must not lead through a symlink.
func noSymlinkSoFar(root, rel string) error {
	p := root
	for _, part := range strings.Split(filepath.Clean(rel), "/") {
		p = filepath.Join(p, part)
		st, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("~/%s is a symlink", strings.TrimPrefix(p, root+"/"))
		}
	}
	return nil
}
