//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/agents"
	"github.com/getjump/airbag/internal/control"
	"github.com/getjump/airbag/internal/diagnostic"
	"github.com/getjump/airbag/internal/policyfs"
	"github.com/getjump/airbag/internal/runtimepolicy"
	"github.com/getjump/airbag/internal/secretfs"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/shim"
	"github.com/getjump/airbag/proxy"
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
	// PID 1 is the supervisor: it holds the raw proxy, control and
	// forward sockets, the FUSE backing fds and, with a runtime policy,
	// the private runtime channel and the exec listener. The agent cannot
	// ptrace it or read /proc/1/mem mainly because the agent's own user
	// namespace has no CAP_SYS_PTRACE over PID 1, which lives in the
	// parent namespace. Setting PR_SET_DUMPABLE=0 is defense in depth:
	// it also blocks the same access where the agent shares the user
	// namespace, and keeps /proc/1 owned by root so hidepid can hide it.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		fatal("protect supervisor", err)
	}
	// The channel exists only for the opt-in runtime options (run.go).
	var client *runtimepolicy.Client
	var profile *runtimepolicy.Profile
	if runtimeOn(s) {
		if s.RuntimeProfile {
			profile = &runtimepolicy.Profile{}
		}
		if client, err = runtimeClient(profile); err != nil {
			fatal("runtime channel", err)
		}
	}
	if err := buildWorld(s, client, profile); err != nil {
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
	code := runAgent(s, ctl, client)
	if profile != nil {
		if err := client.ReportProfile(profile.Snapshot()); err != nil {
			fmt.Fprintf(os.Stderr, "airbag: report runtime profile: %v\n", err)
			code = 125
		}
	}
	os.Exit(code)
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
func buildWorld(s *session.Session, client *runtimepolicy.Client, profile *runtimepolicy.Profile) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	// Separate mounts for the session dir (kept writable) and the real
	// $HOME (source of pass-through binds), made before the host turns
	// read-only. Only a branched $HOME passes anything through; one that
	// is not may not be there at all (HOME=/nonexistent with --no-home).
	if err := bind(s.Dir, s.Dir, false); err != nil {
		return err
	}
	if s.OverHome {
		if err := bind(s.Home, s.MountDir("realhome"), true); err != nil {
			return err
		}
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
		// Paths pass through only when no component is a symlink: a
		// symlink in ~/.claude, say, would make the bind and its
		// read-write flag reach whatever it points at, outside the
		// branch. Such a path is not passed through and stays in the
		// branch (or read-only, where the link leads out of $HOME).
		realhome := s.MountDir("realhome")
		var pass []string
		for _, p := range s.Passthrough {
			p = strings.TrimSuffix(p, "/")
			// Checked before the path need exist: one that is missing
			// because run.go would not create it behind a symlink gets
			// the warning too.
			if err := noSymlinkSoFar(realhome, p); err != nil {
				fmt.Fprintf(os.Stderr, "airbag: warning: ~/%s is not passed through (%v); it stays in the branch\n", p, err)
				continue
			}
			if _, err := os.Lstat(filepath.Join(realhome, p)); err != nil {
				continue // not there: nothing to pass through
			}
			// A hole below it (the project's memory/) that is a link
			// cannot be kept in the branch: the whole directory stays
			// there instead.
			if i := slices.IndexFunc(s.BranchHoles, func(h string) bool {
				return strings.HasPrefix(h, p+"/") && noSymlinkSoFar(realhome, h) != nil
			}); i >= 0 {
				fmt.Fprintf(os.Stderr, "airbag: warning: ~/%s is not passed through (~/%s is a link); it stays in the branch\n", p, s.BranchHoles[i])
				continue
			}
			// Nor a file in it with another name: written through the
			// name here, it would change for real wherever the other is.
			linked, full := hardLinks(realhome, p)
			if len(linked) > 0 {
				fmt.Fprintf(os.Stderr, "airbag: warning: ~/%s is not passed through (~/%s has another hard link); it stays in the branch\n", p, linked[0])
				continue
			}
			if !full {
				fmt.Fprintf(os.Stderr, "airbag: warning: ~/%s is not passed through (it cannot be checked in full for hard links); it stays in the branch\n", p)
				continue
			}
			pass = append(pass, p)
		}
		// A branch hole (a passed-through project's memory/) must stay a
		// copy-on-write view: the real files as lower, the branch as
		// upper, so the agent sees existing memory and its edits and
		// deletions land in the branch. That view is the home overlay's
		// own at the hole's path, which the passthrough bind below would
		// cover, so take a bind of it first and put it back after. A hole
		// whose parent does not pass through needs nothing: it is in the
		// branch already. A hole that cannot be set up fails the session:
		// its parent would pass through whole, and the hole's writes with
		// it.
		type hole struct{ rel, view string }
		var holes []hole
		for i, h := range s.BranchHoles {
			if !slices.ContainsFunc(pass, func(p string) bool { return strings.HasPrefix(h, p+"/") }) {
				continue
			}
			src := filepath.Join(s.Home, h)
			if err := noSymlinkSoFar(s.Home, h); err != nil {
				return fmt.Errorf("branch hole ~/%s: %w", h, err)
			}
			if _, err := os.Lstat(src); errors.Is(err, os.ErrNotExist) {
				// An earlier run of this session deleted the hole or its
				// parent (a project directory that was not passed through
				// then): a whiteout hides the real directory. New
				// directories there are opaque, so the deletion of what
				// was in them stands and the view has a mountpoint again.
				if err := os.MkdirAll(src, 0o700); err != nil {
					return fmt.Errorf("branch hole ~/%s: %w", h, err)
				}
			}
			if err := noSymlink(s.Home, h); err != nil {
				return fmt.Errorf("branch hole ~/%s: %w", h, err)
			}
			if st, err := os.Lstat(src); err != nil || !st.IsDir() {
				return fmt.Errorf("branch hole ~/%s: not a directory", h)
			}
			view := s.MountDir(fmt.Sprintf("hole-%d", i))
			if err := os.MkdirAll(view, 0o700); err != nil {
				return err
			}
			if err := bind(src, view, true); err != nil {
				return err
			}
			// The view must be the home overlay itself, never a real
			// directory that a path could lead to.
			var fs unix.Statfs_t
			if err := unix.Statfs(view, &fs); err != nil || fs.Type != unix.OVERLAYFS_SUPER_MAGIC {
				_ = unix.Unmount(view, unix.MNT_DETACH)
				return fmt.Errorf("branch hole ~/%s: not on the branch of $HOME", h)
			}
			holes = append(holes, hole{h, view})
		}
		for _, p := range pass {
			src, dst := filepath.Join(realhome, p), filepath.Join(s.Home, p)
			if err := bind(src, dst, true); err != nil {
				return err
			}
			if err := setRO(dst, true, false); err != nil {
				return err
			}
		}
		// The mount taken above keeps its own reference to the overlay,
		// so it survives /tmp and the session root being hidden below.
		for _, h := range holes {
			dst := filepath.Join(s.Home, h.rel)
			if err := noSymlink(s.Home, h.rel); err != nil {
				return fmt.Errorf("branch hole ~/%s: %w", h.rel, err)
			}
			if st, err := os.Lstat(dst); err != nil || !st.IsDir() {
				return fmt.Errorf("branch hole ~/%s: not a directory under the passed-through parent", h.rel)
			}
			if err := bind(h.view, dst, true); err != nil {
				return err
			}
			if err := setRO(dst, true, false); err != nil {
				return err
			}
			if err := unix.Unmount(h.view, unix.MNT_DETACH); err != nil {
				return fmt.Errorf("unmount %s: %w", h.view, err)
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
	// Device nodes that are a read into the kernel the filter does not
	// cover: /dev/kmsg is the kernel log (syslog() is refused, but the
	// log is also a readable device), and /dev/userfaultfd opens a
	// userfaultfd without the userfaultfd() syscall. hide() is a no-op
	// when the node is absent.
	for _, p := range []string{"/dev/kmsg", "/dev/userfaultfd"} {
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
	if s.FilePolicy {
		if os.Getenv("AIRBAG_NO_FUSE") != "" {
			return errors.New("--fs-policy requires FUSE; AIRBAG_NO_FUSE is set")
		}
		report := secretReadReporter(func(name, exe string, pid uint32) error {
			return client.Check(runtimepolicy.Request{Source: "fuse", Kind: "secret.read", Target: name, Detail: exe, PID: pid, Secret: true})
		})
		// Match the actual opened backing inode, not just its name: renaming a
		// parent or linking an alias must not lose the original secret's taint.
		type identity struct{ dev, ino uint64 }
		secretInodes := map[identity]string{}
		for _, f := range secrets {
			var st syscall.Stat_t
			if err := syscall.Stat(filepath.Join(s.Workspace, f.Rel), &st); err != nil {
				return err
			}
			secretInodes[identity{st.Dev, st.Ino}] = f.Rel
		}
		beforeRead := func(_ string, pid uint32, fd int) error {
			var st syscall.Stat_t
			if err := syscall.Fstat(fd, &st); err != nil {
				return err
			}
			if rel, ok := secretInodes[identity{st.Dev, st.Ino}]; ok {
				return report(rel, pid)
			}
			return nil
		}
		// Capture BOTH ready views before overmounting either. In particular,
		// workspace commonly lives under HOME. HOME first, workspace last.
		var views []*policyfs.View
		check := client.CheckBatch
		if diagnostic.Config().SkipFileGate {
			check = func([]runtimepolicy.Request) error { return nil }
		}
		options := policyfs.Options{DataCache: policyfs.CacheMode(s.FileCache)}
		if profile != nil {
			options.Observe = func(stat policyfs.OperationStats) {
				profile.Record("fuse."+stat.Operation, stat.Duration, uint64(stat.Requests)) //nolint:gosec // a count, never negative
				if stat.Errno != 0 {
					profile.Record("fuse.error."+stat.Operation, 0, 1)
				}
				if stat.CacheReason != "" {
					profile.Record("cache."+stat.CacheReason, 0, 1)
				}
			}
		}
		for _, path := range []string{s.Home, s.Workspace} {
			// A $HOME that is not there and not branched has nothing to
			// view, and the read-only host keeps it from being made.
			if _, err := os.Lstat(path); path == s.Home && !s.OverHome && errors.Is(err, os.ErrNotExist) {
				continue
			}
			view, err := policyfs.CaptureWithOptions(path, check, beforeRead, options)
			if err != nil {
				return fmt.Errorf("capture policy view %s: %w", path, err)
			}
			views = append(views, view)
		}
		for _, view := range views {
			if _, err := view.Mount(); err != nil {
				return fmt.Errorf("mount file policy: %w", err)
			}
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
	// hidepid=2 hides from the agent every process it cannot access,
	// PID 1 (the supervisor, in the parent user namespace) included, so
	// /proc/1 and other processes' /proc entries are invisible. The
	// agent still sees /proc/self and its own descendants. subset=pid is
	// deliberately NOT set: it would also hide /proc/cpuinfo,
	// /proc/meminfo, /proc/stat and /proc/sys, which node, go and build
	// tools read. Older kernels reject the option, so fall back to a
	// plain mount.
	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if err := unix.Mount("proc", "/proc", "proc", flags, "hidepid=2"); err != nil {
		if err2 := unix.Mount("proc", "/proc", "proc", flags, ""); err2 != nil {
			fmt.Fprintf(os.Stderr, "airbag: warning: private /proc unavailable (%v); host processes stay visible\n", err2)
		} else {
			fmt.Fprintf(os.Stderr, "airbag: warning: /proc without hidepid (%v); other processes stay visible to the agent\n", err)
		}
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
	onRead := secretReadReporter(func(name, exe string, _ uint32) error {
		return control.ReportTaint(control.Taint{File: name, Exe: exe})
	})
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

func secretReadReporter(report func(string, string, uint32) error) secretfs.OnRead {
	self, _ := os.Stat("/proc/self/exe")
	// The open waits until the host has recorded the taint and cut the
	// connections a tainted session may not keep. Reads by one program
	// are reported once; the lock keeps a second reader from slipping
	// through while the first report is in flight.
	var mu sync.Mutex
	reported := map[string]bool{}
	return func(name string, pid uint32) error {
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if st, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid)); err == nil && self != nil && os.SameFile(st, self) {
			return nil // the shell shim reads values to mask them
		}
		mu.Lock()
		defer mu.Unlock()
		if reported[name+exe] {
			return nil
		}
		if err := report(name, exe, pid); err != nil {
			return err
		}
		reported[name+exe] = true
		return nil
	}
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

// closeInheritedFDs marks every open descriptor above stdio
// close-on-exec, so none survives into the agent across its exec. The
// supervisor keeps the descriptors open for itself; it does not exec
// again. CLOSE_RANGE_CLOEXEC (kernel 5.11+) does the whole range at
// once; a kernel without it falls back to walking /proc/self/fd.
func closeInheritedFDs() {
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err == nil {
		return
	}
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		fmt.Fprintf(os.Stderr, "airbag: warning: could not list open fds to close before exec: %v\n", err)
		return
	}
	for _, e := range ents {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd < 3 {
			continue
		}
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC)
	}
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

// noSymlink checks that no component of rel under root is a symlink,
// so a bind of root/rel stays where the path names.
func noSymlink(root, rel string) error {
	p := root
	for _, part := range strings.Split(filepath.Clean(rel), "/") {
		p = filepath.Join(p, part)
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("~/%s is a symlink", strings.TrimPrefix(p, root+"/"))
		}
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
				// The host side bounds idle connections; here an end
				// is passed on as a half-close, and bounded.
				proxy.Relay(c, up, 0, proxy.Drain)
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
					proxy.Relay(c, up, 0, proxy.Drain)
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
func runAgent(s *session.Session, ctl *os.File, client *runtimepolicy.Client) int {
	if s.Strict {
		// The limit is what --strict asks for, so failing to set it stops
		// the run, as a failed filter install does below.
		if err := os.WriteFile("/proc/sys/user/max_user_namespaces", []byte("1"), 0); err != nil {
			fatal("limit user namespaces", err)
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
	// --exec-policy: airbag's exec helper installs the notifying filter
	// in the agent's own process, sends its listener back over fd 3 and
	// execs the agent; PID 1 answers every execve after that.
	var execHost, execChild *os.File
	if s.ExecPolicy {
		var err error
		execHost, execChild, err = socketPair()
		if err != nil {
			fmt.Fprintln(os.Stderr, "airbag: exec controller:", err)
			return 125
		}
		defer func() { _ = execHost.Close() }()
		defer func() { _ = execChild.Close() }()
		cmd = exec.CommandContext(context.Background(), airbagBinInside, append([]string{ExecInitArg, path}, s.Argv...)...) //nolint:gosec // airbag's exec helper, then the command the user asked to run
		// fd 3: the private startup channel.
		cmd.ExtraFiles = []*os.File{execChild}
	}
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
	// Core dumps are capped at 1 byte: a dump could hold secrets the agent
	// had in memory. The limit (soft and hard) is set to 1, not 0,
	// because 0 does not stop a core_pattern that pipes to a handler
	// (systemd-coredump, apport), which the kernel runs regardless of
	// RLIMIT_CORE; dumpable=0 does not carry over either, since exec
	// resets it for the agent. A limit of exactly 1 stops both file dumps
	// and pipe handlers: fs/coredump.c coredump_pipe() aborts a pipe dump
	// when cprm->limit == 1 ("RLIMIT_CORE is set to 1, aborting core"),
	// and the file path is skipped because 1 < binfmt->min_coredump (a
	// page). (Linux v6.18.) The limit is inherited across fork and exec.
	// It does not hold everywhere: any process may lower its own soft
	// limit, and at 0 the pipe handler runs again (under --strict the
	// seccomp filter skips that change, so the limit stays 1); a socket
	// core_pattern ("@" or "@@", Linux 6.16+) ignores the limit and is not
	// covered. airbag doctor reports the host's core_pattern.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 1, Max: 1}); err != nil {
		// Started with a hard limit of 0, which an unprivileged process
		// cannot raise, the limit stays 0, and a pipe core_pattern runs
		// at 0: --strict, which also skips the agent's own changes to the
		// limit, stops the run rather than keep it there.
		if s.Strict {
			fatal("limit core dumps", err)
		}
		fmt.Fprintf(os.Stderr, "airbag: warning: could not limit core dumps: %v\n", err)
	}
	// Close every inherited fd above stdio before the agent starts, so
	// a descriptor leaked from airbag's caller cannot reach it (the runc
	// CVE-2024-21626 class). CLOSE_RANGE_CLOEXEC marks them close-on-exec
	// rather than closing them here: the supervisor keeps its own
	// sockets and the FUSE fd (it never exec()s again), while the agent,
	// which does exec, loses all of them. The ones airbag passes on
	// purpose are stdio (0,1,2) and, under tty, the control fd, which is
	// already close-on-exec; the agent inherits none of them. With
	// --exec-policy the exec helper gets its startup channel as fd 3 and
	// closes it before it execs the agent.
	closeInheritedFDs()
	if err := restrictAgent(s.Strict); err != nil {
		// In --strict mode the filter is part of what the user asked for,
		// so a failure to install it stops the run rather than silently
		// leaving the surface open; by default it is best effort.
		if s.Strict {
			fatal("install seccomp filter", err)
		}
		fmt.Fprintf(os.Stderr, "airbag: warning: %v\n", err)
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "airbag: start agent: %v\n", err)
		return 126
	}
	pgrp := -cmd.Process.Pid
	if s.ExecPolicy {
		_ = execChild.Close()
		listener, err := receiveListener(execHost)
		if err != nil {
			fmt.Fprintln(os.Stderr, "airbag: exec controller:", err)
			_ = syscall.Kill(pgrp, syscall.SIGKILL)
			return 125
		}
		var stop [2]int
		if err := unix.Pipe2(stop[:], unix.O_CLOEXEC); err != nil {
			_ = unix.Close(listener)
			fmt.Fprintln(os.Stderr, "airbag: exec controller:", err)
			_ = syscall.Kill(pgrp, syscall.SIGKILL)
			return 125
		}
		served := make(chan struct{})
		// Once the agent is gone the server stops and is waited for; the
		// listener closes last, so a straggler's execve gets ENOSYS.
		defer func() {
			_ = unix.Close(stop[1])
			<-served
			_ = unix.Close(stop[0])
			_ = unix.Close(listener)
		}()
		go func() {
			defer close(served)
			// Past an error no execve could be answered, so the agent stops
			// rather than run unchecked.
			if err := serveExec(listener, stop[0], client.Check); err != nil {
				fmt.Fprintln(os.Stderr, "airbag: exec controller stopped:", err)
				_ = syscall.Kill(pgrp, syscall.SIGKILL)
			}
		}()
	}
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
