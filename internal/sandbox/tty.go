package sandbox

import (
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The agent never gets the user's terminal. Under a terminal, airbag
// opens a pseudo-terminal, gives its other end to the sandbox, and
// copies bytes between the two, as sudo's use_pty and `docker run -t`
// do. Whatever the agent does to its terminal (pushes input with
// TIOCSTI, changes modes) stays in that pseudo-terminal, never reaches
// the shell the user returns to, and the sandbox runs in a session of
// its own. The user's terminal is put in raw mode for the session, so
// Ctrl-C and Ctrl-Z arrive at the agent's terminal as typed.
//
// Stop and continue cross the boundary on a socket pair: the sandbox's
// PID 1 writes 's' when the agent stops (Ctrl-Z); airbag gives the
// terminal back and stops itself, as a job; when the shell continues
// it, airbag takes the terminal again and writes 'c', and PID 1
// continues the agent.

const (
	ttyStopped  = 's'
	ttyContinue = 'c'
	ttyCtlFd    = 3 // the sandbox's end of the stop/continue channel
)

type terminal struct {
	saved   *unix.Termios
	master  *os.File
	slave   *os.File // the sandbox's end; airbag closes its copy once started
	ctl     *os.File // airbag's end of the stop/continue channel
	ctlPeer *os.File // the sandbox's end
	out     chan struct{}
}

// openTerminal returns nil when stdin or stdout is not a terminal:
// then there is nothing to share, and the sandbox only gets a session
// of its own.
func openTerminal() (*terminal, error) {
	saved, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	if err != nil {
		return nil, nil
	}
	if _, err := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS); err != nil {
		return nil, nil
	}
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	var sfd int
	err = withFd(m, func(fd int) error {
		if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
			return err
		}
		// TIOCGPTPEER opens the peer of this very master, with no lookup
		// of /dev/pts/N by name.
		r, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCGPTPEER,
			uintptr(unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC))
		if e != 0 {
			return e
		}
		sfd = int(r)
		return nil
	})
	if err != nil {
		m.Close()
		return nil, err
	}
	// The agent's terminal starts with the user's settings and size.
	_ = unix.IoctlSetTermios(sfd, unix.TCSETS, saved)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		m.Close()
		unix.Close(sfd)
		return nil, err
	}
	t := &terminal{
		saved:   saved,
		master:  m,
		slave:   os.NewFile(uintptr(sfd), "pty"),
		ctl:     os.NewFile(uintptr(pair[0]), "tty-ctl"),
		ctlPeer: os.NewFile(uintptr(pair[1]), "tty-ctl"),
		out:     make(chan struct{}),
	}
	t.resize()
	return t, nil
}

func withFd(f *os.File, fn func(fd int) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) { ferr = fn(int(fd)) }); err != nil {
		return err
	}
	return ferr
}

func (t *terminal) resize() {
	ws, err := unix.IoctlGetWinsize(int(os.Stdin.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return
	}
	_ = withFd(t.master, func(fd int) error { return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, ws) })
}

func (t *terminal) raw() {
	r := *t.saved
	r.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	r.Oflag &^= unix.OPOST
	r.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	r.Cflag &^= unix.CSIZE | unix.PARENB
	r.Cflag |= unix.CS8
	r.Cc[unix.VMIN], r.Cc[unix.VTIME] = 1, 0
	_ = unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, &r)
}

func (t *terminal) restore() {
	_ = unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, t.saved)
}

// start runs once the sandbox has started: airbag drops its copies of
// the sandbox's ends, so the pseudo-terminal reports EOF when the last
// process inside exits.
func (t *terminal) start() {
	t.slave.Close()
	t.ctlPeer.Close()
	t.raw()
	go func() { _, _ = io.Copy(t.master, os.Stdin) }()
	go func() {
		defer close(t.out)
		buf := make([]byte, 32<<10)
		for {
			n, err := t.master.Read(buf)
			if n > 0 {
				// A write error (the terminal went away) does not stop
				// the reads: the agent must never block on its output.
				_, _ = os.Stdout.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for range winch {
			t.resize()
		}
	}()
	go t.jobControl()
}

func (t *terminal) jobControl() {
	b := make([]byte, 1)
	for {
		if _, err := t.ctl.Read(b); err != nil {
			return
		}
		if b[0] != ttyStopped {
			continue
		}
		t.restore()
		suspend()
		t.raw()
		t.resize()
		_, _ = t.ctl.Write([]byte{ttyContinue})
	}
}

// suspend stops airbag the way a shell job stops on Ctrl-Z, and returns
// once the shell continues it. The signal is sent to this thread, so it
// is delivered before the call returns. In a process group without job
// control the kernel discards it, and the agent just continues.
func suspend() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_ = unix.Tgkill(unix.Getpid(), unix.Gettid(), unix.SIGTSTP)
}

// finish waits until the agent's output is copied, then gives the user
// the terminal back. Every process inside is gone once PID 1 exits, so
// the wait is short; the timeout only guards against a stray holder.
func (t *terminal) finish() {
	select {
	case <-t.out:
	case <-time.After(5 * time.Second):
	}
	t.restore()
	t.master.Close()
	t.ctl.Close()
}
