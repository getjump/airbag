//go:build linux

package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/runtimepolicy"
	"github.com/getjump/airbag/internal/session"
)

// runtimeFD is the private runtime channel in the sandbox's PID 1. Fd 3
// is the tty control channel, or /dev/null without a tty (run.go).
const runtimeFD = 4

// runtimeOn reports whether the session uses one of the opt-in runtime
// options. Without them there is no runtime channel and no fd 4, as
// before these options existed.
func runtimeOn(s *session.Session) bool {
	return s.FilePolicy || s.ExecPolicy || s.RuntimeProfile
}

func socketPair() (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[0]), "supervisor"), os.NewFile(uintptr(fds[1]), "sandbox"), nil
}

func runtimeClient(profile *runtimepolicy.Profile) (*runtimepolicy.Client, error) {
	unix.CloseOnExec(runtimeFD)
	f := os.NewFile(runtimeFD, "runtime-policy")
	c, err := net.FileConn(f)
	_ = f.Close() // FileConn holds its own dup
	if err != nil {
		return nil, err
	}
	return runtimepolicy.NewClientWithProfile(c, profile), nil
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
