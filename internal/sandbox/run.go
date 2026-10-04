//go:build linux

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

func Run(s *session.Session, allow proxy.Allowlist, pol *policy.Policy) (int, error) {
	gate := policy.NewGate(pol, s.Dir)
	restoreLabels(gate, s)
	log, err := effects.Open(s.EffectsPath())
	if err != nil {
		return 1, err
	}
	defer func() { _ = log.Close() }()

	pl, err := net.Listen("unix", s.ProxySock())
	if err != nil {
		return 1, err
	}
	defer pl.Close()
	px := proxy.New(allow, log)
	px.Gate = gate
	if px.Creds, px.CA, err = setupCredentials(s, pol.Credentials); err != nil {
		return 1, err
	}
	mr := mirror.New(filepath.Join(session.Root(), "mirror"), log)
	mr.Tainted = gate.Tainted
	mr.Pinned = mirror.FindPins(s.Workspace) // read from the real workspace, before the agent starts
	px.Mirror = mr
	// tcp:// forwards: one unix socket each, bridged inside the sandbox
	// to 127.0.0.1:PORT (startForwards).
	var fws []*forwarder
	var fls []net.Listener // each serves until the session ends
	defer func() {
		for _, l := range fls {
			_ = l.Close()
		}
	}()
	for i, f := range s.Forwards {
		_ = os.Remove(s.ForwardSock(i))
		fl, err := net.Listen("unix", s.ForwardSock(i))
		if err != nil {
			return 1, err
		}
		fls = append(fls, fl)
		fw := newForwarder(f, gate, log)
		fws = append(fws, fw)
		go fw.serve(fl)
	}
	// Once the session reads a secret, connections it opened earlier to
	// hosts outside the core set close before the read returns.
	gate.Labels().OnAdd(func(l taint.Label, _ string) {
		if l == taint.Secret {
			px.Cut(proxy.DefaultAllow, "secret-taint")
			for _, fw := range fws {
				fw.cut()
			}
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
	defer func() { _ = box.Close() }()
	ctl := &control.Server{Box: box, Log: log, Steps: steps.NewTracker(s), Gate: gate, Root: s.Workspace}
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
	cmd := exec.Command(self, InitArg, s.Dir) //nolint:gosec // airbag itself, as the sandbox's PID 1
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
