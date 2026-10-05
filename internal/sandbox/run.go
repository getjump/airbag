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

// stop records the end of a run: resume, apply and discard refuse a
// session that is still marked running.
func stop(s *session.Session, code int) error {
	s.Status, s.ExitCode, s.Ended = session.StatusStopped, code, time.Now()
	return s.Save()
}

// stopFailed records a run of an optional runtime that failed after the
// session existed, so the session stays reachable for review and discard.
func stopFailed(s *session.Session, code int, err error) (int, error) {
	if code == 0 {
		code = 1
	}
	return code, errors.Join(err, stop(s, code))
}

func Run(s *session.Session, allow proxy.Allowlist, pol *policy.Policy) (int, error) {
	optional := s.Backend != "" && s.Backend != "native"
	if optional {
		if err := prepareRuntimeWorkspace(s); err != nil {
			return stopFailed(s, 1, err)
		}
	}
	// An optional runtime's agent works in the clone; control requests
	// name its paths.
	root := s.Workspace
	if s.Clone {
		root = s.CloneDir()
	}
	host, err := startHostServices(s, allow, pol, hostEndpoints{ProxyNetwork: "unix", ProxyAddress: s.ProxySock(), ControlRoot: root, Forwards: true})
	if err != nil {
		if optional {
			return stopFailed(s, 1, err)
		}
		return 1, err
	}
	defer func() { _ = host.Close() }()

	if optional {
		code, err := runOptional(s)
		if err != nil {
			return stopFailed(s, code, err)
		}
		return code, stop(s, code)
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
			return 1, fmt.Errorf("branch hole ~/%s: %w", h, err)
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
