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

	"github.com/getjump/airbag/internal/control"
	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/proxy"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/steps"
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
}

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
	go func() { _ = px.Serve(pl) }()

	cl, err := net.Listen("unix", s.ControlSock())
	if err != nil {
		return 1, err
	}
	defer cl.Close()
	ctl := &control.Server{Box: outbox.Open(s.OutboxPath()), Log: log, Steps: steps.NewTracker(s), Gate: gate}
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
	cmd := exec.Command(self, InitArg, s.Dir)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: s.UID, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: s.GID, Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
	}
	// Ctrl-C belongs to the agent; airbag stays up until the agent exits.
	// Catch, don't ignore: an ignored signal stays ignored across exec,
	// and the agent would start deaf to Ctrl-C.
	swallow(os.Interrupt, syscall.SIGQUIT)
	defer signal.Reset(os.Interrupt, syscall.SIGQUIT)

	err = cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		return 1, fmt.Errorf("start sandbox: %w%s", err, userNSHint())
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
