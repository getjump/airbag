package sandbox

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/control"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/shim"
)

// Inside the sandbox the egress proxy is reachable only here.
const (
	ProxyAddr        = "127.0.0.1:3128"
	proxySockInside  = "/run/airbag/proxy.sock"
	airbagBinInside  = shim.BinDir + "/airbag"
	runtimeDirFormat = "/run/user/%d"
)

// Init runs as PID 1 in the new namespaces, as root of the new user
// namespace (mapped to the real user). It never returns.
func Init(dir string) {
	signal.Ignore(os.Interrupt, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU)
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
	os.Exit(runAgent(s))
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

	if err := privateRun(s); err != nil {
		return err
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

// privateRun mounts an empty /run with airbag's sockets and shims.
func privateRun(s *session.Session) error {
	if err := unix.Mount("tmpfs", "/run", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
		return fmt.Errorf("tmpfs /run: %w", err)
	}
	if err := os.MkdirAll(shim.BinDir, 0o755); err != nil {
		return err
	}
	for src, dst := range map[string]string{
		s.ProxySock():    proxySockInside,
		s.ControlSock():  control.SocketInSandbox,
		"/proc/self/exe": airbagBinInside,
	} {
		if err := os.WriteFile(dst, nil, 0o600); err != nil {
			return err
		}
		if err := bind(src, dst, false); err != nil {
			return err
		}
	}
	if err := os.Symlink(airbagBinInside, filepath.Join(shim.BinDir, "git")); err != nil {
		return err
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
		return nil
	}
	if st.IsDir() {
		return unix.Mount("tmpfs", p, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0700")
	}
	return bind("/dev/null", p, false)
}

// loopbackUp brings up lo in the new network namespace. There is no
// other interface: the only way out is the proxy bridge.
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
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
	l, err := net.Listen("tcp", ProxyAddr)
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
				up, err := net.Dial("unix", proxySockInside)
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

// runAgent starts the agent in a nested user namespace with the real
// uid, so tools that refuse to run as root (Claude Code's bypass mode)
// work, and the mounts above are locked against the agent.
func runAgent(s *session.Session) int {
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
	cmd := exec.Command(path, s.Argv[1:]...)
	cmd.Args[0] = s.Argv[0]
	cmd.Env = env
	cmd.Dir = s.Cwd
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: s.UID, HostID: 0, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: s.GID, HostID: 0, Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "airbag: start agent: %v\n", err)
		return 126
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigs {
			_ = cmd.Process.Signal(sig)
		}
	}()
	// As PID 1 we reap every orphan until the agent itself exits.
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 1
		}
		if pid == cmd.Process.Pid {
			if ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			return ws.ExitStatus()
		}
	}
}

func agentEnv(s *session.Session) []string {
	drop := map[string]bool{
		"SSH_AUTH_SOCK": true, "SSH_AGENT_PID": true, "GPG_AGENT_INFO": true,
		"DBUS_SESSION_BUS_ADDRESS": true, "DISPLAY": true, "WAYLAND_DISPLAY": true,
		"XAUTHORITY": true, "DOCKER_HOST": true, "KRB5CCNAME": true,
		"ALL_PROXY": true, "all_proxy": true,
	}
	set := map[string]string{
		"HTTPS_PROXY": "http://" + ProxyAddr, "https_proxy": "http://" + ProxyAddr,
		"HTTP_PROXY": "http://" + ProxyAddr, "http_proxy": "http://" + ProxyAddr,
		"NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1",
		"XDG_RUNTIME_DIR": fmt.Sprintf(runtimeDirFormat, s.UID),
		"AIRBAG_SESSION":  s.ID,
	}
	var env []string
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if drop[k] {
			continue
		}
		if _, ok := set[k]; ok {
			continue
		}
		if k == "PATH" {
			v = shim.BinDir + ":" + v
		}
		env = append(env, k+"="+v)
	}
	for k, v := range set {
		env = append(env, k+"="+v)
	}
	return env
}

func lookPath(name string, env []string) (string, error) {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			for _, dir := range filepath.SplitList(v) {
				p := filepath.Join(dir, name)
				if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
					return p, nil
				}
			}
		}
	}
	return "", os.ErrNotExist
}
