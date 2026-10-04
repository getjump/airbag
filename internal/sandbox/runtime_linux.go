//go:build linux

package sandbox

import (
	"net"
	"os"

	"github.com/getjump/airbag/internal/runtimepolicy"
	"golang.org/x/sys/unix"
)

const runtimeFD = 4
const ExecInitArg = "__airbag_exec_init"

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
	f.Close()
	if err != nil {
		return nil, err
	}
	return runtimepolicy.NewClientWithProfile(c, profile), nil
}
