//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/agents"
	"github.com/getjump/airbag/internal/control"
	"github.com/getjump/airbag/internal/secretfs"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/shim"
)

// Inside the sandbox the egress proxy is reachable only here.
const (
	ProxyAddr        = "127.0.0.1:3128"
	proxySockInside  = "/run/airbag/proxy.sock"
	runtimeDirFormat = "/run/user/%d"
)

var airbagBinInside = shim.BinDir + "/airbag"

// Init runs as PID 1 in the new namespaces, as root of the new user
// namespace (mapped to the real user). With tty, its stdio is the
// agent's pseudo-terminal and fd 3 the stop/continue channel (tty.go).
// It never returns.
func Init(dir string, tty bool) {
	swallow(os.Interrupt, syscall.SIGQUIT)
	s, err := session.Load(dir)
	if err != nil {
		fatal("load session", err)
	}
	if err := buildWorld(s); err != nil {
		fatal("build sandbox", err)
	}
	if err := loopbackUp(); err != nil {
		fatal("loopback", err)
	}
	if err := startBridge(); err != nil {
		fatal("proxy bridge", err)
	}
	if err := startForwards(s); err != nil {
		fatal("tcp forward", err)
	}
	var ctl *os.File
	if tty {
		syscall.CloseOnExec(ttyCtlFd)
		ctl = os.NewFile(ttyCtlFd, "tty-ctl")
	}
	os.Exit(runAgent(s, ctl))
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "airbag: %s: %v\n", what, err)
	os.Exit(125)
}

// buildWorld makes the agent's view of the machine:
//   - the host is read-only, except for the overlays below;
//   - the workspace and $HOME are copy-on-write branches of the real ones;
//   - agent state in $HOME passes through, credentials are hidden;
//   - /run, /tmp, /var/tmp and /dev/shm are private, so host sockets
//     (docker.sock, D-Bus, ssh-agent, X11, Wayland) are out of reach.
func buildWorld(s *session.Session) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	// Separate mounts for the session dir (kept writable) and the real
	// $HOME (source of pass-through binds), made before the host turns
	// read-only.
	if err := bind(s.Dir, s.Dir, false); err != nil {
		return err
	}
	if err := bind(s.Home, s.MountDir("realhome"), true); err != nil {
		return err
	}
	// Open .env files now: once the workspace is branched, their paths
	// lead to the copies airbag serves.
	secrets := secretfs.Open(s.Workspace)
	if err := setRO("/", true, true); err != nil {
		return fmt.Errorf("make host read-only: %w", err)
	}
	if err := setRO(s.Dir, false, false); err != nil {
		return err
	}
	// /dev stays writable for ttys and /dev/null; device perms still apply.
	if err := setRO("/dev", true, false); err != nil {
		return err
	}

	if err := overlay(s.Workspace, s.WSUpper(), s.WSWork(), s.MountDir("ws")); err != nil {
		return fmt.Errorf("workspace overlay: %w", err)
	}
	if s.OverHome {
		if err := overlay(s.Home, s.HomeUpper(), s.HomeWork(), s.Home); err != nil {
			return fmt.Errorf("home overlay: %w", err)
		}
	}
	if err := bind(s.MountDir("ws"), s.Workspace, false); err != nil {
		return err
	}

	if s.OverHome {
		for _, p := range s.Passthrough {
			p = strings.TrimSuffix(p, "/")
			src, dst := filepath.Join(s.MountDir("realhome"), p), filepath.Join(s.Home, p)
			if _, err := os.Lstat(src); err != nil {
				continue
			}
			if err := bind(src, dst, true); err != nil {
				return err
			}
			if err := setRO(dst, true, false); err != nil {
				return err
			}
		}
	}
	for _, p := range s.Hidden {
		if err := hide(filepath.Join(s.Home, p)); err != nil {
			return err
		}
	}
	for _, p := range s.HiddenHost {
		if err := hide(p); err != nil {
			return fmt.Errorf("hide %s: %w", p, err)
		}
	}

	if err := agentConfig(s); err != nil {
		fmt.Fprintf(os.Stderr, "airbag: warning: agent hooks not installed: %v\n", err)
	}
	if err := privateRun(s); err != nil {
		return err
	}
	if len(secrets) > 0 {
		// Without FUSE the session cannot see reads of the secret files,
		// so they are hidden rather than left readable untracked.
		err := errors.New("AIRBAG_NO_FUSE is set")
		if os.Getenv("AIRBAG_NO_FUSE") == "" {
			err = serveSecrets(s, secrets)
		}
		if err != nil {
			for _, f := range secrets {
				if herr := hide(filepath.Join(s.Workspace, f.Rel)); herr != nil {
					return fmt.Errorf("secret %s is neither tracked (%w) nor hidden: %w", f.Rel, err, herr)
				}
			}
			fmt.Fprintf(os.Stderr, "airbag: warning: %d secret files are hidden from the agent: reads cannot be tracked (%v)\n", len(secrets), err)
		}
	}
	for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if _, err := os.Stat(d); err == nil {
			if err := unix.Mount("tmpfs", d, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777"); err != nil {
				return fmt.Errorf("tmpfs %s: %w", d, err)
			}
		}
	}
	// The session dir holds the branch itself; the agent must not see it.
	if root := session.Root(); !strings.HasPrefix(root, "/var/tmp/") && !strings.HasPrefix(root, "/tmp/") {
		if err := unix.Mount("tmpfs", root, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0700"); err != nil {
			return fmt.Errorf("hide session root: %w", err)
		}
	}
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		fmt.Fprintf(os.Stderr, "airbag: warning: private /proc unavailable (%v); host processes stay visible\n", err)
	}
	return nil
}

// agentConfig puts airbag's hooks into agents' managed (policy) config.
// /etc gets its own branch so the files can be added; the directories
// are then made read-only mounts, which the agent cannot undo.
func agentConfig(s *session.Session) error {
	if err := overlay("/etc", s.EtcUpper(), s.EtcWork(), "/etc"); err != nil {
		return fmt.Errorf("/etc overlay: %w", err)
	}
	dir := agents.ClaudeManagedSettingsDir
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // /etc in the sandbox: the agent reads its managed settings here
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "90-airbag.json"), agents.ClaudeManagedSettings(), 0o444); err != nil { //nolint:gosec // managed settings the agent must read and must not change
		return err
	}
	top := filepath.Dir(dir)
	if err := bind(top, top, true); err != nil {
		return err
	}
	if err := setRO(top, true, true); err != nil {
		return err
	}
	// Codex: only when the host has no managed requirements of its own,
	// which airbag would otherwise replace.
	req := agents.CodexRequirementsPath
	if _, err := os.Stat(req); err == nil {
		fmt.Fprintf(os.Stderr, "airbag: note: %s exists on this host; Codex hooks are not installed\n", req)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(req), 0o755); err != nil { //nolint:gosec // /etc in the sandbox: the agent reads its requirements here
		return err
	}
	if err := os.WriteFile(req, agents.CodexRequirements(), 0o444); err != nil { //nolint:gosec // requirements the agent must read and must not change
		return err
	}
	cdir := filepath.Dir(req)
	if err := bind(cdir, cdir, true); err != nil {
		return err
	}
	return setRO(cdir, true, true)
}

// serveSecrets puts the workspace's secret files behind secretfs: every
// read by anything but airbag itself taints the session.
func serveSecrets(s *session.Session, files []secretfs.File) error {
	dir := "/run/airbag/secrets"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	self, _ := os.Stat("/proc/self/exe")
	// The open waits until the host has recorded the taint and cut the
	// connections a tainted session may not keep. Reads by one program
	// are reported once; the lock keeps a second reader from slipping
	// through while the first report is in flight.
	var mu sync.Mutex
	reported := map[string]bool{}
	onRead := func(name string, pid uint32) error {
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if st, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid)); err == nil && self != nil && os.SameFile(st, self) {
			return nil // the shell shim reads values to mask them
		}
		mu.Lock()
		defer mu.Unlock()
		if reported[name+exe] {
			return nil
		}
		if err := control.ReportTaint(control.Taint{File: name, Exe: exe}); err != nil {
			return err
		}
		reported[name+exe] = true
		return nil
	}
	if _, err := secretfs.Mount(dir, files, onRead); err != nil {
		return err
	}
	for _, f := range files {
		if err := bind(filepath.Join(dir, f.Rel), filepath.Join(s.Workspace, f.Rel), false); err != nil {
			return err
		}
	}
	return nil
}

// privateRun mounts an empty /run with airbag's sockets and shims.
func privateRun(s *session.Session) error {
	if err := unix.Mount("tmpfs", "/run", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
		return fmt.Errorf("tmpfs /run: %w", err)
	}
	if err := os.MkdirAll(shim.BinDir, 0o755); err != nil { //nolint:gosec // the shims' directory, which every program in the sandbox searches
		return err
	}
	socks := map[string]string{
		s.ProxySock():    proxySockInside,
		s.ControlSock():  control.SocketInSandbox,
		"/proc/self/exe": airbagBinInside,
	}
	for i := range s.Forwards {
		socks[s.ForwardSock(i)] = forwardSockInside(i)
	}
	for src, dst := range map[string]string{s.CACert(): caCertInside, s.CABundle(): caBundleInside} {
		if _, err := os.Stat(src); err == nil {
			socks[src] = dst
		}
	}
	for src, dst := range socks {
		if err := os.WriteFile(dst, nil, 0o600); err != nil {
			return err
		}
		if err := bind(src, dst, false); err != nil {
			return err
		}
	}
	for _, name := range shimNames(s) {
		if err := os.Symlink(airbagBinInside, filepath.Join(shim.BinDir, name)); err != nil {
			return err
		}
	}
	return os.MkdirAll(fmt.Sprintf(runtimeDirFormat, s.UID), 0o700)
}

func bind(src, dst string, rec bool) error {
	flags := uintptr(unix.MS_BIND)
	if rec {
		flags |= unix.MS_REC
	}
	if err := unix.Mount(src, dst, "", flags, ""); err != nil {
		return fmt.Errorf("bind %s -> %s: %w", src, dst, err)
	}
	return nil
}

func setRO(path string, recursive, ro bool) error {
	attr := &unix.MountAttr{}
	if ro {
		attr.Attr_set = unix.MOUNT_ATTR_RDONLY
	} else {
		attr.Attr_clr = unix.MOUNT_ATTR_RDONLY
	}
	flags := 0
	if recursive {
		flags = unix.AT_RECURSIVE
	}
	if err := unix.MountSetattr(unix.AT_FDCWD, path, uint(flags), attr); err != nil {
		return fmt.Errorf("mount_setattr %s: %w", path, err)
	}
	return nil
}

func overlay(lower, upper, work, target string) error {
	for _, p := range []string{lower, upper, work} {
		if strings.ContainsAny(p, ",:") {
			return fmt.Errorf("path %q contains ',' or ':', unsupported by overlayfs options", p)
		}
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,userxattr", lower, upper, work)
	return unix.Mount("overlay", target, "overlay", 0, opts)
}

func hide(p string) error {
	st, err := os.Lstat(p)
	if err != nil || st.Mode()&os.ModeSymlink != 0 {
		return nil //nolint:nilerr // what PID 1 cannot stat, the agent, with fewer rights, cannot open either
	}
	if st.IsDir() {
		return unix.Mount("tmpfs", p, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0700")
	}
	return bind("/dev/null", p, false)
}

// loopbackUp brings up lo in the new network namespace. There is no
// other interface: the only way out is the proxy bridge.
//
//nolint:gosec // unsafe: SIOC[GS]IFFLAGS take a pointer to the ifreq, whose flags sit after the name
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var ifr [unix.IFNAMSIZ + 24]byte
	copy(ifr[:], "lo")
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return e
	}
	flags := *(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ]))
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags | unix.IFF_UP
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return e
	}
	return nil
}

// startBridge forwards 127.0.0.1:3128 inside the sandbox to the host
// proxy's unix socket.
func startBridge() error {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", ProxyAddr)
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				up, err := (&net.Dialer{}).DialContext(context.Background(), "unix", proxySockInside)
				if err != nil {
					return
				}
				defer up.Close()
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
				go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	return nil
}

// Where the agent finds the session CA (sandbox/creds.go).
const (
	caCertInside   = "/run/airbag/ca.pem"
	caBundleInside = "/run/airbag/ca-bundle.pem"
)

func forwardSockInside(i int) string { return fmt.Sprintf("/run/airbag/fwd-%d.sock", i) }

// startForwards listens on 127.0.0.1:PORT in the sandbox for each
// tcp:// forward and relays to airbag outside, which connects on.
func startForwards(s *session.Session) error {
	for i, f := range s.Forwards {
		if strconv.Itoa(f.Port) == strings.TrimPrefix(ProxyAddr, "127.0.0.1:") {
			return fmt.Errorf("%s: port %d is airbag's proxy inside the sandbox", f, f.Port)
		}
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", f.Port))
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		sock := forwardSockInside(i)
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					up, err := (&net.Dialer{}).DialContext(context.Background(), "unix", sock)
					if err != nil {
						return
					}
					defer up.Close()
					done := make(chan struct{}, 2)
					go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
					go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
					<-done
				}()
			}
		}()
	}
	return nil
}

// runAgent starts the agent in a nested user namespace with the real
// uid, so tools that refuse to run as root (Claude Code's bypass mode)
// work, and the mounts above are locked against the agent.
//
// In strict mode the agent's namespace is the last one: the limit set
// here (as bubblewrap's --disable-userns does) keeps the agent from
// creating user namespaces, and with them the kernel surface reachable
// only from inside one. It is off by default because the agents' own
// sandboxes and Chromium's sandbox need user namespaces.
//
// The agent leads a process group of its own, the foreground one on its
// pseudo-terminal, so Ctrl-C and Ctrl-Z reach it and not PID 1.
func runAgent(s *session.Session, ctl *os.File) int {
	if s.Strict {
		if err := os.WriteFile("/proc/sys/user/max_user_namespaces", []byte("1"), 0); err != nil {
			fmt.Fprintf(os.Stderr, "airbag: warning: the agent can create user namespaces: %v\n", err)
		}
	}
	env := agentEnv(s)
	path := s.Argv[0]
	if !strings.Contains(path, "/") {
		p, err := lookPath(path, env)
		if err != nil {
			fmt.Fprintf(os.Stderr, "airbag: %s: not found\n", path)
			return 127
		}
		path = p
	}
	cmd := exec.CommandContext(context.Background(), path, s.Argv[1:]...) //nolint:gosec // the command the user asked to run in the sandbox
	cmd.Args[0] = s.Argv[0]
	cmd.Env = env
	cmd.Dir = s.Cwd
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: s.UID, HostID: 0, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: s.GID, HostID: 0, Size: 1}},
		GidMappingsEnableSetgroups: false,
		Setpgid:                    true,
	}
	if ctl != nil {
		cmd.SysProcAttr.Foreground = true
		cmd.SysProcAttr.Ctty = 0
	}
	if err := restrictAgent(); err != nil {
		fmt.Fprintf(os.Stderr, "airbag: warning: %v\n", err)
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "airbag: start agent: %v\n", err)
		return 126
	}
	pgrp := -cmd.Process.Pid
	// Signals airbag forwards from outside go to the agent's group, as
	// a terminal would send them.
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigs {
			_ = syscall.Kill(pgrp, sig.(syscall.Signal))
		}
	}()
	if ctl != nil {
		go func() {
			b := make([]byte, 1)
			for {
				if _, err := ctl.Read(b); err != nil {
					return
				}
				if b[0] == ttyContinue {
					_ = syscall.Kill(pgrp, syscall.SIGCONT)
				}
			}
		}()
	}
	// As PID 1 we reap every orphan until the agent itself exits.
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WUNTRACED, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 1
		}
		if pid != cmd.Process.Pid {
			continue
		}
		switch {
		case ws.Stopped():
			if ctl != nil {
				_, _ = ctl.Write([]byte{ttyStopped})
			}
		case ws.Signaled():
			return 128 + int(ws.Signal())
		default:
			return ws.ExitStatus()
		}
	}
}

func agentEnv(s *session.Session) []string {
	bundle := ""
	if _, err := os.Stat(caBundleInside); err == nil {
		bundle = caBundleInside
	}
	return agentEnvFor(s, ProxyAddr, shim.BinDir, fmt.Sprintf(runtimeDirFormat, s.UID), credEnv(s, caCertInside, bundle))
}
