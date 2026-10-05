//go:build linux

// Package sandbox starts the agent in a branch of the world.
//
// Host side (this file): starts the egress proxy and the control socket,
// then re-executes airbag as PID 1 of fresh user, mount, PID, network
// and IPC namespaces (init.go). That init process builds the branch and
// starts the agent in a nested user namespace under the user's own uid.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/proxy"
)

func Run(s *session.Session, allow proxy.Allowlist, pol *policy.Policy) (int, error) {
	// The roots are checked again right before the first thing made for
	// the run: since the session was created or resumed, either could
	// have become another directory.
	if err := s.CheckRoots(); err != nil {
		return 1, fmt.Errorf("%w; session %s was not started", err, s.ID)
	}
	// An empty mode is durable: a session from before the option, or one
	// that never set it.
	switch s.RuntimeAudit {
	case "", "durable", "buffered":
	default:
		return 1, fmt.Errorf("invalid runtime audit mode %q", s.RuntimeAudit)
	}
	host, err := startHostServices(s, allow, pol, hostEndpoints{ProxyNetwork: "unix", ProxyAddress: s.ProxySock(), ControlRoot: s.Workspace, Forwards: true})
	if err != nil {
		return 1, err
	}
	defer func() { _ = host.Close() }()
	if err := prepareHome(s); err != nil {
		return 1, err
	}

	self, err := os.Executable()
	if err != nil {
		return 1, err
	}
	tty, err := openTerminal()
	if err != nil {
		return 1, fmt.Errorf("pseudo-terminal: %w", err)
	}
	// The opt-in runtime options get a private channel to PID 1 as fd 4;
	// without them the sandbox starts as it did before they existed.
	var rt *runtimeHost
	if runtimeOn(s) {
		if rt, err = startRuntime(s, host.Gate, host.Log); err != nil {
			return 1, fmt.Errorf("runtime channel: %w", err)
		}
		defer func() { _ = rt.finish(s) }() // an early return; the normal path reports it below
	}
	cmd := exec.CommandContext(context.Background(), self, InitArg, s.Dir) //nolint:gosec // airbag itself, as the sandbox's PID 1
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
	if rt != nil {
		if tty == nil {
			cmd.ExtraFiles = []*os.File{rt.placeholder} // fd 3: unused without a tty
		}
		cmd.ExtraFiles = append(cmd.ExtraFiles, rt.child) // fd 4: runtimeFD
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
			_ = tty.slave.Close()
			_ = tty.ctlPeer.Close()
			_ = tty.master.Close()
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
	if rt != nil {
		// PID 1 holds the only other end: its exit is the channel's EOF.
		_ = rt.child.Close()
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
	// A runtime audit that did not reach the log is a failed run, never
	// a clean stop.
	var rtErr error
	if rt != nil {
		if rtErr = rt.finish(s); rtErr != nil {
			code = 125
		}
	}
	s.Status = session.StatusStopped
	s.ExitCode = code
	s.Ended = time.Now()
	return code, errors.Join(rtErr, s.Save())
}

func userNSHint() string {
	if b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil && len(b) > 0 && b[0] == '1' {
		return "\nairbag: this system restricts unprivileged user namespaces (Ubuntu 23.10+ AppArmor);" +
			" run `airbag doctor` for the one-time fix"
	}
	return ""
}

// prepareHome makes what init passes through in a branched $HOME. A
// $HOME that is not branched passes nothing through, so nothing is made
// in it: it may be one the session could not record (HomeUnrecorded).
func prepareHome(s *session.Session) error {
	if !s.OverHome {
		return nil
	}
	// Pass-through dirs must exist on the host, or the agent would
	// create them inside the branch and lose them on discard. A path
	// through a symlink is not created: MkdirAll would follow it out of
	// $HOME, and init refuses to pass it through anyway.
	for _, p := range s.Passthrough {
		if strings.HasSuffix(p, "/") && noSymlinkSoFar(s.Home, p) == nil {
			_ = os.MkdirAll(filepath.Join(s.Home, p), 0o700)
		}
	}
	// A branch hole (a passed-through project's memory/) needs to exist
	// in the real $HOME: as a mountpoint inside the passed-through parent,
	// and as the lower layer of the copy-on-write view put on it (init.go).
	// Under a symlink it is skipped like its parent, which init then
	// leaves in the branch.
	for _, h := range s.BranchHoles {
		if noSymlinkSoFar(s.Home, h) != nil {
			continue
		}
		if err := os.MkdirAll(filepath.Join(s.Home, h), 0o700); err != nil {
			return fmt.Errorf("branch hole ~/%s: %w", h, err)
		}
	}
	return nil
}
