//go:build darwin

package sandbox

// The macOS prototype. There are no namespaces or overlayfs, so:
//
//   - the workspace branch is an APFS clone (cp -c) in the session; the
//     agent works there, review compares it with the real workspace;
//   - one deny-first Seatbelt profile wraps the agent's process tree:
//     writes only to the clone, the session's temp and cache
//     directories and the agent's own state; credentials and the
//     workspace's secret files unreadable; outbound traffic only to
//     airbag's proxy on a localhost port and its control socket;
//   - $HOME has no branch: it is read-only apart from agent state, and
//     caches point into the session;
//   - secret files are hidden, not tracked (no FUSE): the agent cannot
//     read them at all;
//   - no agent hooks: Claude Code's managed settings need root on macOS.
//
// What stays the same: the proxy and mirror, the shims, the outbox, the
// effect log, policies, review and apply.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/proxy"
)

// Init exists on Linux only: macOS has no namespaces to start in.
func Init(string, bool) {
	fmt.Fprintln(os.Stderr, "airbag: internal error: no sandbox init on macOS")
	os.Exit(125)
}

func Run(s *session.Session, allow proxy.Allowlist, pol *policy.Policy) (int, error) {
	// The roots are checked again right before the clone and the
	// profile: since the session was created or resumed, either could
	// have become another directory.
	if err := s.CheckRoots(); err != nil {
		return 1, fmt.Errorf("%w; session %s was not started", err, s.ID)
	}
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		return 1, errors.New("sandbox-exec not found: airbag needs macOS's Seatbelt")
	}
	if err := cloneWorkspace(s); err != nil {
		return 1, err
	}
	host, err := startHostServices(s, allow, pol, hostEndpoints{ProxyNetwork: "tcp", ProxyAddress: "127.0.0.1:0", ControlRoot: s.CloneDir()})
	if err != nil {
		return 1, err
	}
	defer func() { _ = host.Close() }()
	port := host.ProxyAddr.(*net.TCPAddr).Port

	self, err := os.Executable()
	if err != nil {
		return 1, err
	}
	binDir := filepath.Join(s.RunDir(), "bin")
	tmp, cache := filepath.Join(s.Dir, "tmp"), filepath.Join(s.Dir, "cache")
	for _, d := range []string{binDir, tmp, cache} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return 1, err
		}
	}
	for _, name := range shimNames(s) {
		link := filepath.Join(binDir, name)
		_ = os.Remove(link)
		if err := os.Symlink(self, link); err != nil {
			return 1, err
		}
	}

	rel, err := filepath.Rel(s.Workspace, s.Cwd)
	if err != nil || strings.HasPrefix(rel, "..") {
		rel = "."
	}
	// The agent works in the clone, so Claude Code names its project
	// directory after the clone's path: that one passes through too, and
	// is made with its memory/ before the run (the profile does not let
	// the agent create project directories).
	pass, holes := ClaudeProjectState(filepath.Join(s.CloneDir(), rel), s.CloneDir())
	s.Passthrough = appendNew(s.Passthrough, pass...)
	s.BranchHoles = appendNew(s.BranchHoles, holes...)
	prof, err := macProfile(s, port, tmp, cache)
	if err != nil {
		return 1, err
	}
	bundle := ""
	if _, err := os.Stat(s.CABundle()); err == nil {
		bundle = s.CABundle()
	}
	env := agentEnvFor(s, fmt.Sprintf("127.0.0.1:%d", port), binDir, tmp, credEnv(s, s.CACert(), bundle))
	env = append(env,
		"AIRBAG_CONTROL="+s.ControlSock(), "AIRBAG_SHIM_DIR="+binDir, "TMPDIR="+tmp+"/",
		"XDG_CACHE_HOME="+cache, "GOCACHE="+filepath.Join(cache, "go-build"),
		"GOMODCACHE="+filepath.Join(cache, "gomod"), "npm_config_cache="+filepath.Join(cache, "npm"),
		"PIP_CACHE_DIR="+filepath.Join(cache, "pip"), "UV_CACHE_DIR="+filepath.Join(cache, "uv"),
		"CARGO_HOME="+filepath.Join(cache, "cargo"),
	)
	path := s.Argv[0]
	if !strings.Contains(path, "/") {
		p, err := lookPath(path, env)
		if err != nil {
			return 127, fmt.Errorf("%s: not found", path)
		}
		path = p
	}
	cmd := exec.CommandContext(context.Background(), "/usr/bin/sandbox-exec", append([]string{"-p", prof.String(), path}, s.Argv[1:]...)...) //nolint:gosec // the command the user asked to run, inside the profile
	cmd.Dir = filepath.Join(s.CloneDir(), rel)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	fmt.Fprintf(os.Stderr, "airbag: macOS prototype: the agent works in a clone at %s; ~ is read-only apart from agent state; secret files are hidden, not tracked\n", cmd.Dir)

	// Ctrl-C belongs to the agent, which shares the terminal here.
	swallow(os.Interrupt, syscall.SIGQUIT)
	defer signal.Reset(os.Interrupt, syscall.SIGQUIT)
	if err = startAgent(s, cmd); err == nil {
		err = cmd.Wait()
	}
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		return 1, fmt.Errorf("start the agent: %w", err)
	}
	s.Status = session.StatusStopped
	s.ExitCode = code
	s.Ended = time.Now()
	return code, s.Save()
}

// startAgent starts cmd as the agent, holding the session's agent lock.
// Nothing ends the agent with airbag on macOS: killed, airbag would leave
// it writing in the clone, and a rollback could start beside it. The lock
// passes to the agent from before it runs anything and lasts as long as
// the agent does, or a process of its that keeps the descriptor; airbag
// keeps none of its own. The agent never gets the run lock, which stays
// airbag's. An agent lock that cannot be taken starts no agent.
func startAgent(s *session.Session, cmd *exec.Cmd) error {
	lock, err := s.LockAgent()
	if err != nil {
		return fmt.Errorf("take the agent lock: %w", err)
	}
	defer func() { _ = lock.Close() }()
	cmd.ExtraFiles = append(cmd.ExtraFiles, lock)
	return cmd.Start()
}

// cloneWorkspace makes the branch on the first run: an APFS clone is
// instant and takes no space until files change. Off APFS, cp falls
// back to a full copy.
func cloneWorkspace(s *session.Session) error {
	if fi, err := os.Lstat(s.CloneDir()); err == nil {
		// A resumed session keeps its clone. An older airbag made the
		// clone of a workspace named through a link a link to the real
		// files; the profile would then let the agent write them.
		if !fi.IsDir() {
			return fmt.Errorf("the clone of session %s is not a directory (an older airbag made it from a linked workspace); discard the session", s.ID)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.CloneDir()), 0o700); err != nil {
		return err
	}
	// cp -R copies a link named on its command line as a link, so a
	// workspace named through one would give a clone that is a link to
	// the real files. It copies from where the link leads.
	src, err := filepath.EvalSymlinks(s.Workspace)
	if err != nil {
		return fmt.Errorf("resolve the workspace %s: %w", s.Workspace, err)
	}
	out, err := exec.CommandContext(context.Background(), "/bin/cp", "-c", "-R", src, s.CloneDir()).CombinedOutput() //nolint:gosec // absolute paths of the session's own workspace and clone
	if err != nil {
		_ = os.RemoveAll(s.CloneDir())
		fmt.Fprintf(os.Stderr, "airbag: APFS clone failed (%s); copying instead\n", strings.TrimSpace(string(out)))
		if out, err := exec.CommandContext(context.Background(), "/bin/cp", "-R", src, s.CloneDir()).CombinedOutput(); err != nil { //nolint:gosec // absolute paths of the session's own workspace and clone
			return fmt.Errorf("copy the workspace: %w: %s", err, out)
		}
	}
	return nil
}
