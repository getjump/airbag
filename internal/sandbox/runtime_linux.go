//go:build linux

package sandbox

import (
	"net"
	"os"

	"golang.org/x/sys/unix"

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
