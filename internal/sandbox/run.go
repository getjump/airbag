// Package sandbox starts the agent in a branch of the world.
//
// Host side (this file): starts the egress proxy and the control socket,
// then re-executes airbag as PID 1 of fresh user, mount, PID, network
// and IPC namespaces (init.go). That init process builds the branch and
// starts the agent in a nested user namespace under the user's own uid.
package sandbox

import (
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

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/control"
	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/mirror"
	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/proxy"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/steps"
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

func Run(s *session.Session, allow proxy.Allowlist, pol *policy.Policy) (int, error) {
	gate := policy.NewGate(pol, s.Dir)
	log, err := effects.Open(s.EffectsPath())
	if err != nil {
		return 1, err
	}
	defer log.Close()

	pl, err := net.Listen("unix", s.ProxySock())
	if err != nil {
		return 1, err
	}
	defer pl.Close()
	px := proxy.New(allow, log)
	px.Gate = gate
	mr := mirror.New(filepath.Join(session.Root(), "mirror"), log)
	mr.Tainted = gate.Tainted
	px.Mirror = mr
	// Once the session reads a secret, connections it opened earlier to
	// hosts outside the core set close before the read returns.
	gate.Labels().OnAdd(func(l taint.Label, _ string) {
		if l == taint.Secret {
			px.Cut(proxy.DefaultAllow, "secret-taint")
		}
	})
	go func() { _ = px.Serve(pl) }()

	cl, err := net.Listen("unix", s.ControlSock())
	if err != nil {
		return 1, err
	}
	defer cl.Close()
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		return 1, err
	}
	defer box.Close()
	ctl := &control.Server{Box: box, Log: log, Steps: steps.NewTracker(s), Gate: gate}
	go func() { _ = ctl.Serve(cl) }()

	// Pass-through dirs must exist on the host, or the agent would
	// create them inside the branch and lose them on discard.
	for _, p := range s.Passthrough {
		if strings.HasSuffix(p, "/") {
			_ = os.MkdirAll(filepath.Join(s.Home, p), 0o700)
		}
	}

	self, err := os.Executable()
	if err != nil {
		return 1, err
	}
	tty, err := openTerminal()
	if err != nil {
		return 1, fmt.Errorf("pseudo-terminal: %w", err)
	}
	cmd := exec.Command(self, InitArg, s.Dir)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// The sandbox gets a session of its own, so the user's terminal is
	// never its controlling terminal (tty.go).
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: s.UID, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: s.GID, Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
		Setsid:                     true,
	}
	if tty != nil {
		cmd.Args = append(cmd.Args, "tty")
		cmd.Stdin, cmd.Stdout = tty.slave, tty.slave
		if _, err := unix.IoctlGetTermios(int(os.Stderr.Fd()), unix.TCGETS); err == nil {
			cmd.Stderr = tty.slave
		}
		cmd.ExtraFiles = []*os.File{tty.ctlPeer} // fd 3: ttyCtlFd
		cmd.SysProcAttr.Setctty = true
		cmd.SysProcAttr.Ctty = 0
	}
	// Signals for the agent go to the sandbox's PID 1, which passes them
	// on: the agent is no longer in airbag's process group, so Ctrl-C
	// on a terminal airbag does not share reaches it this way. Catch,
	// don't ignore: an ignored signal stays ignored across exec, and the
	// agent would start deaf to Ctrl-C.
	sigs := make(chan os.Signal, 8)
	fwd := []os.Signal{os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP}
	signal.Notify(sigs, fwd...)
	defer signal.Reset(fwd...)

	if err := cmd.Start(); err != nil {
		if tty != nil {
			tty.slave.Close()
			tty.ctlPeer.Close()
			tty.master.Close()
		}
		return 1, fmt.Errorf("start sandbox: %w%s", err, userNSHint())
	}
	go func() {
		for sig := range sigs {
			_ = cmd.Process.Signal(sig)
		}
	}()
	if tty != nil {
		tty.start()
	}
	err = cmd.Wait()
	if tty != nil {
		tty.finish()
	}
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		return 1, fmt.Errorf("sandbox: %w", err)
	}
	s.Status = session.StatusStopped
	s.ExitCode = code
	s.Ended = time.Now()
	return code, s.Save()
}

func userNSHint() string {
	if b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil && len(b) > 0 && b[0] == '1' {
		return "\nairbag: this system restricts unprivileged user namespaces (Ubuntu 23.10+ AppArmor);" +
			" run `airbag doctor` for the one-time fix"
	}
	return ""
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
