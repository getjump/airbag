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
	"encoding/json"
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
	"github.com/getjump/airbag/internal/runtimepolicy"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/steps"
	"github.com/getjump/airbag/internal/taint"
)

func Run(s *session.Session, allow proxy.Allowlist, pol *policy.Policy) (int, error) {
	// An empty mode is durable: a session from before the option, or one
	// that never set it.
	switch s.RuntimeAudit {
	case "", "durable", "buffered":
	default:
		return 1, fmt.Errorf("invalid runtime audit mode %q", s.RuntimeAudit)
	}
	gate := policy.NewGate(pol, s.Dir)
	restoreLabels(gate, s)
	log, err := effects.Open(s.EffectsPath())
	if err != nil {
		return 1, err
	}
	defer func() { _ = log.Close() }()

	pl, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", s.ProxySock())
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
		fl, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", s.ForwardSock(i))
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

	cl, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", s.ControlSock())
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
	// The opt-in runtime options get a private channel to PID 1 as fd 4;
	// without them the sandbox starts as it did before they existed.
	var rt *runtimeHost
	if runtimeOn(s) {
		if rt, err = startRuntime(s, gate, log); err != nil {
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

// runtimeHost serves the runtime channel: PID 1's file and exec checks
// go through the gate and into the effect log before they are allowed.
type runtimeHost struct {
	conn        net.Conn
	child       *os.File // the sandbox's end, fd 4 in PID 1
	placeholder *os.File // fd 3 when there is no tty
	audit       *effects.BufferedAudit
	opts        runtimepolicy.Options
	done        chan error
	finished    bool
	err         error
}

func startRuntime(s *session.Session, gate *policy.Gate, log *effects.Log) (*runtimeHost, error) {
	host, child, err := socketPair()
	if err != nil {
		return nil, err
	}
	conn, err := net.FileConn(host)
	_ = host.Close() // FileConn holds its own dup
	if err != nil {
		_ = child.Close()
		return nil, err
	}
	placeholder, err := os.Open(os.DevNull)
	if err != nil {
		_ = conn.Close()
		_ = child.Close()
		return nil, err
	}
	rt := &runtimeHost{conn: conn, child: child, placeholder: placeholder, done: make(chan error, 1)}
	if s.RuntimeAudit == "buffered" {
		rt.audit = effects.NewBufferedAudit(log, effects.BufferOptions{})
		rt.opts.Audit = rt.audit
	}
	if s.RuntimeProfile {
		rt.opts.Profile = &runtimepolicy.Profile{}
	}
	go func() { rt.done <- runtimepolicy.ServeWithOptions(conn, gate, log, rt.opts) }()
	return rt, nil
}

// finish stops the producer before it drains the buffered audit, so a
// failed flush shows in the result. It runs once; later calls return
// the first result.
func (rt *runtimeHost) finish(s *session.Session) error {
	if rt.finished {
		return rt.err
	}
	rt.finished = true
	_ = rt.child.Close()
	_ = rt.placeholder.Close()
	var errs []error
	select {
	case err := <-rt.done:
		if err != nil {
			errs = append(errs, fmt.Errorf("runtime controller: %w", err))
		}
	case <-time.After(30 * time.Second):
		_ = rt.conn.Close()
		errs = append(errs, errors.New("runtime controller shutdown timeout"))
		<-rt.done
	}
	if rt.audit != nil {
		if err := rt.audit.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if rt.opts.Profile != nil {
		mode := s.RuntimeAudit
		if mode == "" {
			mode = "durable"
		}
		profile := struct {
			Run       int                           `json:"run"`
			AuditMode string                        `json:"audit_mode"`
			Runtime   runtimepolicy.ProfileSnapshot `json:"runtime"`
			Buffered  *effects.BufferStats          `json:"buffered,omitempty"`
		}{Run: s.Runs, AuditMode: mode, Runtime: rt.opts.Profile.Snapshot()}
		if rt.audit != nil {
			stats := rt.audit.Stats()
			profile.Buffered = &stats
		}
		data, err := json.MarshalIndent(profile, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(s.Dir, fmt.Sprintf("runtime-profile-%d.json", s.Runs)), append(data, '\n'), 0o600)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("write runtime profile: %w", err))
		}
	}
	rt.err = errors.Join(errs...)
	return rt.err
}

func userNSHint() string {
	if b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil && len(b) > 0 && b[0] == '1' {
		return "\nairbag: this system restricts unprivileged user namespaces (Ubuntu 23.10+ AppArmor);" +
			" run `airbag doctor` for the one-time fix"
	}
	return ""
}
