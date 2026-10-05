//go:build linux

package sandbox

import (
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/getjump/airbag/internal/agents"
	"github.com/getjump/airbag/internal/session"
	"golang.org/x/sys/unix"
)

const guestConfigPath = "/run/airbag/config.json"

type guestConfig struct {
	Backend              string   `json:"backend"`
	Strict               bool     `json:"strict,omitempty"`
	GeneratedRecoveryDir bool     `json:"generated_recovery_dir,omitempty"`
	Argv                 []string `json:"argv"`
	Env                  []string `json:"env"`
	Cwd                  string   `json:"cwd"`
	Workspace            string   `json:"workspace"`
	UID                  int      `json:"uid"`
	GID                  int      `json:"gid"`
}

func optionalHostReady(backend string) error {
	if _, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS); err == nil {
		return fmt.Errorf("%s currently supports noninteractive stdin only; use native for a terminal", backend)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	image, err := elf.Open(self)
	if err != nil {
		return err
	}
	defer func() { _ = image.Close() }()
	for _, program := range image.Progs {
		if program.Type == elf.PT_INTERP {
			return fmt.Errorf("optional runtimes require a static Airbag binary; build with CGO_ENABLED=0")
		}
	}
	if backend == "microvm" {
		if _, err := exec.LookPath("mkfs.ext4"); err != nil {
			return fmt.Errorf("microvm requires mkfs.ext4: %w", err)
		}
	}
	if !filepath.IsAbs(session.Root()) {
		return fmt.Errorf("optional runtime requires an absolute AIRBAG_HOME")
	}
	if len(session.Root()+"/s-abcdef/run/proxy.sock") >= 108 {
		return fmt.Errorf("optional runtime session root is too long for Unix sockets; choose a shorter AIRBAG_HOME")
	}
	return nil
}

func prepareRuntimeWorkspace(s *session.Session) error {
	if _, err := os.Stat(s.CloneDir()); err == nil {
		return nil
	}
	if err := os.MkdirAll(s.CloneDir(), 0o700); err != nil {
		return err
	}
	// A pipe avoids a second full intermediate archive. Import confines paths;
	// source symlinks are preserved, never followed into host HOME.
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { err := exportWorkspace(s.Workspace, writer); _ = writer.CloseWithError(err); done <- err }()
	err := importWorkspace(s.CloneDir(), reader)
	_ = reader.CloseWithError(err)
	copyErr := <-done
	if err != nil || copyErr != nil {
		_ = os.RemoveAll(s.CloneDir())
		return errors.Join(err, copyErr)
	}
	return nil
}

func runOptional(s *session.Session) (int, error) {
	dir := filepath.Join(s.Dir, "runtime")
	// Nothing agent-writable is used as provider configuration or executable.
	if err := os.RemoveAll(dir); err != nil {
		return 1, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 1, err
	}
	root := filepath.Join(dir, "rootfs")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return 1, err
	}
	cmd := exec.CommandContext(context.Background(), "/bin/cp", "-a", "--reflink=auto", "--", s.Runtime.RootFS+"/.", root) //nolint:gosec // operator-supplied trusted rootfs, separate from workspace
	if out, err := cmd.CombinedOutput(); err != nil {
		return 1, fmt.Errorf("stage rootfs: %w: %s", err, out)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return 1, err
	}
	defer func() { _ = r.Close() }()
	for _, path := range []string{"run/airbag/bin", "run/airbag/sockets", "dev", "proc", "sys", "tmp", "home/agent", s.CloneDir()[1:]} {
		if err := r.MkdirAll(path, 0o755); err != nil {
			return 1, err
		}
	}
	for _, path := range []string{agents.ClaudeManagedSettingsDir[1:], filepath.Dir(agents.CodexRequirementsPath)[1:]} {
		if err := r.MkdirAll(path, 0o755); err != nil {
			return 1, err
		}
	}
	if err := r.WriteFile(agents.ClaudeManagedSettingsDir[1:]+"/90-airbag.json", agents.ClaudeManagedSettings(), 0o444); err != nil {
		return 1, err
	}
	if _, err := r.Stat(agents.CodexRequirementsPath[1:]); os.IsNotExist(err) {
		if err := r.WriteFile(agents.CodexRequirementsPath[1:], agents.CodexRequirements(), 0o444); err != nil {
			return 1, err
		}
	}
	self, err := os.Executable()
	if err != nil {
		return 1, err
	}
	binary, err := os.ReadFile(self)
	if err != nil {
		return 1, err
	}
	if err := r.WriteFile("run/airbag/bin/airbag", binary, 0o755); err != nil {
		return 1, err
	}
	for _, name := range shimNames(s) {
		_ = r.Remove("run/airbag/bin/" + name)
		if err := r.Symlink("airbag", "run/airbag/bin/"+name); err != nil {
			return 1, err
		}
	}
	bundle := ""
	for _, cert := range []struct{ src, dst string }{{s.CACert(), "ca.pem"}, {s.CABundle(), "ca-bundle.pem"}} {
		if b, err := os.ReadFile(cert.src); err == nil {
			if err := r.WriteFile("run/airbag/"+cert.dst, b, 0o644); err != nil {
				return 1, err
			}
			if cert.dst == "ca-bundle.pem" {
				bundle = "/run/airbag/" + cert.dst
			}
		}
	}
	extra := credEnv(s, "/run/airbag/ca.pem", bundle)
	for k, v := range map[string]string{"HOME": "/home/agent", "PATH": "/run/airbag/bin:/usr/local/bin:/usr/bin:/bin", "TMPDIR": "/tmp", "AIRBAG_HOME": "", "AIRBAG_WORKSPACE": s.CloneDir(), "AIRBAG_CONTROL": "/run/airbag/ctl.sock", "AIRBAG_SHIM_DIR": "/run/airbag/bin"} {
		extra[k] = v
	}
	uid, gid := s.UID, s.GID
	if s.Backend == "microvm" && uid == 0 {
		uid, gid = 1000, 1000
	}
	cwd := s.CloneDir()
	if rel, err := filepath.Rel(s.Workspace, s.Cwd); err == nil && pathWithin(s.Cwd, s.Workspace) {
		cwd = filepath.Join(cwd, rel)
	}
	cfg := guestConfig{Backend: s.Backend, Strict: s.Strict, Argv: s.Argv, Env: agentEnvFor(s, ProxyAddr, "/run/airbag/bin", "/tmp", extra), Cwd: cwd, Workspace: s.CloneDir(), UID: uid, GID: gid}
	if s.Backend == "microvm" {
		_, err := os.Lstat(filepath.Join(s.CloneDir(), "lost+found"))
		cfg.GeneratedRecoveryDir = os.IsNotExist(err)
	}
	if err := writeJSONFile(r, "run/airbag/config.json", cfg); err != nil {
		return 1, err
	}
	if err := r.Chmod("run/airbag/config.json", 0o444); err != nil {
		return 1, err
	}
	if s.Backend == "microvm" {
		if err := r.Symlink("sockets/ctl.sock", "run/airbag/ctl.sock"); err != nil {
			return 1, err
		}
	}
	if s.Backend == "gvisor" {
		return runGVisor(s, dir, root)
	}
	return runMicroVM(s, dir, root)
}

func writeJSONFile(root *os.Root, path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return root.WriteFile(path, b, 0o600)
}

func runGVisor(s *session.Session, dir, root string) (int, error) {
	mounts := []map[string]any{
		{"destination": "/proc", "type": "proc", "source": "proc"},
		{"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
		{"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": []string{"nosuid", "nodev", "mode=1777"}},
		{"destination": "/home/agent", "type": "tmpfs", "source": "tmpfs", "options": []string{"nosuid", "nodev", "mode=1777"}},
		{"destination": s.CloneDir(), "type": "bind", "source": s.CloneDir(), "options": []string{"bind", "rw", "nosuid", "nodev"}},
	}
	for src, dst := range map[string]string{s.ProxySock(): "/run/airbag/proxy.sock", s.ControlSock(): "/run/airbag/ctl.sock"} {
		mounts = append(mounts, map[string]any{"destination": dst, "type": "bind", "source": src, "options": []string{"bind", "ro", "nosuid", "nodev"}})
	}
	// Rootless runsc maps the host owner of the exported files to namespace UID
	// zero. Use that virtual identity with no capabilities; it has no host-root
	// identity and cannot gain one through no_new_privs or user namespaces.
	caps := map[string][]string{"bounding": {}, "effective": {}, "inheritable": {}, "permitted": {}, "ambient": {}}
	config := map[string]any{
		"ociVersion": "1.0.2", "root": map[string]any{"path": root, "readonly": true},
		"process": map[string]any{"terminal": false, "user": map[string]int{"uid": 0, "gid": 0}, "args": []string{"/run/airbag/bin/airbag", GuestArg}, "env": []string{"PATH=/run/airbag/bin:/usr/bin:/bin"}, "cwd": "/", "noNewPrivileges": true, "capabilities": caps},
		"mounts":  mounts,
		"linux": map[string]any{"namespaces": []map[string]string{{"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}, {"type": "network"}},
			"devices": []map[string]any{
				{"path": "/dev/null", "type": "c", "major": 1, "minor": 3, "fileMode": 438, "uid": 0, "gid": 0},
				{"path": "/dev/zero", "type": "c", "major": 1, "minor": 5, "fileMode": 438, "uid": 0, "gid": 0},
				{"path": "/dev/random", "type": "c", "major": 1, "minor": 8, "fileMode": 438, "uid": 0, "gid": 0},
				{"path": "/dev/urandom", "type": "c", "major": 1, "minor": 9, "fileMode": 438, "uid": 0, "gid": 0},
			},
			// runsc loads this only with --oci-seccomp (below), and its
			// errno is always EPERM. clone3 is refused in the guest instead
			// (guestFilter), with the ENOSYS glibc needs to fall back to clone.
			"seccomp": map[string]any{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": []map[string]any{
				{"names": []string{"unshare", "setns"}, "action": "SCMP_ACT_ERRNO", "errnoRet": 1},
				{"names": []string{"clone"}, "action": "SCMP_ACT_ERRNO", "errnoRet": 1, "args": []map[string]any{{"index": 0, "value": syscall.CLONE_NEWUSER, "valueTwo": syscall.CLONE_NEWUSER, "op": "SCMP_CMP_MASKED_EQ"}}},
			}},
		},
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return 1, err
	}
	err = writeJSONFile(r, "config.json", config)
	_ = r.Close()
	if err != nil {
		return 1, err
	}
	common := []string{"--root=" + filepath.Join(dir, "state"), "--rootless=" + strconv.FormatBool(os.Getuid() != 0)}
	defer func() {
		cmd := exec.CommandContext(context.Background(), s.Runtime.Binary, append(common, "delete", "--force", s.ID)...) //nolint:gosec // trusted runsc, fixed runtime operation
		_ = cmd.Run()
		// Run as root, runsc leaves --network=none's namespace mounted in
		// its state directory, which resume and discard then cannot remove.
		_ = unix.Unmount(filepath.Join(dir, "state", "null-netns"), unix.MNT_DETACH|unix.UMOUNT_NOFOLLOW)
	}()
	args := append(append([]string{}, common...), "--platform=systrap", "--oci-seccomp", "--network=none", "--host-uds=open", "--file-access=shared", "--overlay2=none", "run", "--bundle="+dir, s.ID)
	return executeProvider(s.Runtime.Binary, args)
}

func executeProvider(binary string, args []string) (int, error) {
	cmd := exec.CommandContext(context.Background(), binary, args...) //nolint:gosec // explicitly selected trusted runtime, not a guest-supplied executable
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return 1, err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case sig := <-sigs:
				_ = cmd.Process.Signal(sig)
			}
		}
	}()
	err := cmd.Wait()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	return 0, err
}

func ext4Image(source, path string, size int64) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	err = f.Truncate(size)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	cmd := exec.CommandContext(context.Background(), "mkfs.ext4", "-q", "-F", "-d", source, path) //nolint:gosec // image creation from host-owned session data; no untrusted image parsing
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("make guest image: %w: %s", err, out)
	}
	return nil
}

func runMicroVM(s *session.Session, dir, root string) (int, error) {
	rootImage, workImage := filepath.Join(dir, "root.ext4"), filepath.Join(dir, "work.ext4")
	if err := ext4Image(root, rootImage, 2<<30); err != nil {
		return 1, err
	}
	if err := ext4Image(s.CloneDir(), workImage, 10<<30); err != nil {
		return 1, err
	}
	sock := filepath.Join(s.Dir, "v.sock")
	// Firecracker does not unlink its listening socket on clean shutdown. The
	// previous provider has exited before a stopped session can be resumed.
	if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
		return 1, err
	}
	defer func() { _ = os.Remove(sock) }()
	var listeners []net.Listener
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	for port, target := range map[int]string{4000: s.ProxySock(), 4001: s.ControlSock()} {
		path := sock + "_" + strconv.Itoa(port)
		_ = os.Remove(path)
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
		if err != nil {
			return 1, err
		}
		listeners = append(listeners, l)
		go serveRelay(l, func() (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(context.Background(), "unix", target)
		})
	}
	// The result channel is not attestation. A compromised guest can forge its
	// exit code and tree; the host treats both as untrusted and still requires apply.
	exportPath := sock + "_4002"
	_ = os.Remove(exportPath)
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", exportPath)
	if err != nil {
		return 1, err
	}
	listeners = append(listeners, l)
	imported := make(chan struct {
		code int
		err  error
	}, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			imported <- struct {
				code int
				err  error
			}{1, err}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
		var result [1]byte
		if _, err := io.ReadFull(conn, result[:]); err != nil {
			imported <- struct {
				code int
				err  error
			}{1, err}
			return
		}
		stage := filepath.Join(s.Dir, "ws", "export")
		_ = os.RemoveAll(stage)
		err = os.MkdirAll(stage, 0o700)
		if err == nil {
			err = importWorkspace(stage, conn)
		}
		// Wait for the VMM to exit before publishing a result. Native review/apply
		// paths are used only after this validation and atomic replacement.
		imported <- struct {
			code int
			err  error
		}{int(result[0]), err}
	}()
	config := map[string]any{
		"boot-source":    map[string]any{"kernel_image_path": s.Runtime.Kernel, "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/run/airbag/bin/airbag " + GuestArg},
		"drives":         []map[string]any{{"drive_id": "rootfs", "path_on_host": rootImage, "is_root_device": true, "is_read_only": true}, {"drive_id": "work", "path_on_host": workImage, "is_root_device": false, "is_read_only": false}},
		"machine-config": map[string]int{"vcpu_count": 1, "mem_size_mib": 2048},
		"vsock":          map[string]any{"guest_cid": 3, "uds_path": sock},
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return 1, err
	}
	err = writeJSONFile(r, "firecracker.json", config)
	_ = r.Close()
	if err != nil {
		return 1, err
	}
	code, err := executeProvider(s.Runtime.Binary, []string{"--no-api", "--config-file", filepath.Join(dir, "firecracker.json")})
	if err != nil || code != 0 {
		return code, err
	}
	select {
	case result := <-imported:
		if result.err != nil {
			return 1, fmt.Errorf("guest export: %w", result.err)
		}
		backup := filepath.Join(s.Dir, "ws", "previous")
		_ = os.RemoveAll(backup)
		if err := os.Rename(s.CloneDir(), backup); err != nil {
			return 1, err
		}
		if err := os.Rename(filepath.Join(s.Dir, "ws", "export"), s.CloneDir()); err != nil {
			_ = os.Rename(backup, s.CloneDir())
			return 1, err
		}
		_ = os.RemoveAll(backup)
		return result.code, nil
	case <-time.After(10 * time.Second):
		return 1, fmt.Errorf("guest terminated without a complete workspace export")
	}
}
