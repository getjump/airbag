//go:build darwin

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/getjump/airbag/internal/agents"
	"github.com/getjump/airbag/internal/seatbelt"
	"github.com/getjump/airbag/internal/session"
)

type runSplitIn struct {
	Session         *session.Session
	Path, Self, Cwd string
	Env             []string
	Profile         seatbelt.Profile
}

func runSplit(in runSplitIn) (code int, runErr error) {
	s := in.Session
	if s.Runs > 1 {
		return 1, errors.New("split execution currently supports new sessions only; resume is refused (no fallback)")
	}
	version := splitCommand([]string{in.Path, "--version"}, in.Profile)
	version.Dir, version.Env = in.Cwd, in.Env
	version.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var versionOutput bytes.Buffer
	version.Stdout = &versionOutput
	if err := startAgent(s, version); err != nil {
		return 1, err
	}
	versionDone := waitSplitProcess(version)
	select {
	case <-versionDone:
		if !version.ProcessState.Success() {
			return 1, errors.New("executor version check failed")
		}
	case <-time.After(5 * time.Second):
		stopSplitProcess(version, versionDone)
		return 1, errors.New("executor version check timed out")
	}
	if err := agents.CheckSplitVersion(versionOutput.Bytes()); err != nil {
		return 1, err
	}
	var err error
	control := filepath.Join(s.Dir, "control")
	if err := os.Mkdir(control, 0o700); err != nil {
		return 1, err
	}
	control, err = filepath.EvalSymlinks(control)
	if err != nil {
		return 1, err
	}
	neutral, state := filepath.Join(control, "cwd"), filepath.Join(control, "state")
	paths := splitProfileIn{Control: control, Tmp: filepath.Join(control, "tmp"), Cache: filepath.Join(control, "cache"), Socket: filepath.Join(control, "exec.sock"), RPC: filepath.Join(control, "rpc.sock")}
	for _, dir := range []string{neutral, paths.Tmp, paths.Cache} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return 1, err
		}
	}
	if err := agents.PrepareLaunch(agents.PrepareLaunchIn{ID: s.Launcher, Source: agents.LaunchSource(s.Launcher, s.Home), State: state}); err != nil {
		return 1, err
	}
	commands, err := agents.SplitCommands(agents.SplitCommandsIn{Binary: in.Path, Self: in.Self, Socket: paths.Socket, RPC: paths.RPC, Argv: s.Argv})
	if err != nil {
		return 1, err
	}
	if err := os.WriteFile(filepath.Join(state, "environments.toml"), []byte(commands.Registry), 0o600); err != nil {
		return 1, err
	}
	clone, err := filepath.EvalSymlinks(in.Cwd)
	if err != nil {
		return 1, err
	}
	workerProfile, coordinatorProfile := splitProfiles(s, in.Profile, paths)
	worker := splitCommand(commands.Worker, workerProfile)
	worker.Dir, worker.Env, worker.Stderr = clone, in.Env, os.Stderr
	workerIn, err := worker.StdinPipe()
	if err != nil {
		return 1, err
	}
	workerOut, err := worker.StdoutPipe()
	if err != nil {
		_ = workerIn.Close()
		return 1, err
	}
	defer func() { _ = workerIn.Close(); _ = workerOut.Close() }()
	worker.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := s.BeginExecutor(); err != nil {
		return 1, err
	}
	if err := startAgent(s, worker); err != nil {
		return 1, errors.Join(fmt.Errorf("start private executor (no fallback): %w", err), s.EndExecutor())
	}
	workerDone := waitSplitProcess(worker)
	shutdownStarted := false
	defer func() {
		_ = workerIn.Close()
		cleanEOF := true
		select {
		case <-workerDone:
		case <-time.After(5 * time.Second):
			cleanEOF = false
			stopSplitProcess(worker, workerDone)
		}
		if !shutdownStarted || !cleanEOF || !worker.ProcessState.Success() {
			code = 1
			runErr = errors.Join(runErr, s.CheckExecutorStopped())
		} else {
			if err := s.EndExecutor(); err != nil {
				code = 1
				runErr = errors.Join(runErr, err)
			}
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	executor, err := (&net.ListenConfig{}).Listen(ctx, "unix", paths.Socket)
	if err != nil {
		return 1, err
	}
	defer func() { _ = executor.Close() }()
	rpc, err := (&net.ListenConfig{}).Listen(ctx, "unix", paths.RPC)
	if err != nil {
		return 1, err
	}
	defer func() { _ = rpc.Close() }()
	bridgeDone := make(chan error, 1)
	go func() { bridgeDone <- bridgeSplitExecutor(ctx, executor, workerIn, workerOut) }()
	defer func() { cancel(); _ = executor.Close(); <-bridgeDone }()
	env := append(append([]string{}, in.Env...), "CODEX_HOME="+state, "TMPDIR="+paths.Tmp+"/", "XDG_CACHE_HOME="+paths.Cache)
	server := splitCommand(commands.Server, coordinatorProfile)
	server.Dir, server.Env, server.Stderr = neutral, env, os.Stderr
	server.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	serverIn, err := server.StdinPipe()
	if err != nil {
		return 1, err
	}
	serverOut, err := server.StdoutPipe()
	if err != nil {
		_ = serverIn.Close()
		return 1, err
	}
	if err := server.Start(); err != nil {
		_ = serverIn.Close()
		_ = serverOut.Close()
		return 1, err
	}
	serverDone := waitSplitProcess(server)
	defer stopSplitProcess(server, serverDone)
	proxyDone := make(chan struct{})
	var proxyErr error
	go func() {
		proxyErr = agents.RunSplitProxy(ctx, agents.SplitProxyIn{Binding: agents.SplitBinding{Neutral: neutral, Clone: clone}, Listener: rpc, Input: serverIn, Output: serverOut})
		close(proxyDone)
	}()
	defer func() { cancel(); <-proxyDone }()
	tui := splitCommand(commands.TUI, coordinatorProfile)
	tui.Dir, tui.Env = neutral, env
	tui.Stdin, tui.Stdout, tui.Stderr = os.Stdin, os.Stdout, os.Stderr
	swallow(os.Interrupt, syscall.SIGQUIT)
	defer signal.Reset(os.Interrupt, syscall.SIGQUIT)
	if err := tui.Start(); err != nil {
		return 1, err
	}
	tuiDone := waitSplitProcess(tui)
	defer stopSplitProcess(tui, tuiDone)
	fmt.Fprintln(os.Stderr, "airbag: experimental split execution: private coordinator cannot access the workspace; executor is bound to the clone; no host fallback")
	finish := func() (int, error) {
		shutdownStarted = true
		_ = workerIn.Close()
		select {
		case <-tuiDone:
		case <-time.After(3 * time.Second):
			return 1, errors.New("private TUI did not exit after transport closed")
		}
		code := tui.ProcessState.ExitCode()
		s.Status, s.ExitCode, s.Ended = session.StatusStopped, code, time.Now()
		return code, s.Save()
	}
	select {
	case <-tuiDone:
		return finish()
	case <-workerDone:
		if worker.ProcessState.Success() {
			select {
			case <-proxyDone:
				if agents.SplitClientClosed(proxyErr) {
					return finish()
				}
			case <-time.After(100 * time.Millisecond):
			}
		}
		return 1, errors.New("private executor stopped; session quarantined (no fallback)")
	case <-serverDone:
		select {
		case <-proxyDone:
			if agents.SplitClientClosed(proxyErr) {
				return finish()
			}
		case <-time.After(100 * time.Millisecond):
		}
		return 1, errors.New("private coordinator stopped; session quarantined (no fallback)")
	case <-proxyDone:
		if agents.SplitClientClosed(proxyErr) {
			return finish()
		}
		return 1, fmt.Errorf("private RPC transport stopped; session quarantined (no fallback): %w", proxyErr)
	}

}

func splitCommand(argv []string, profile seatbelt.Profile) *exec.Cmd {
	return &exec.Cmd{Path: "/usr/bin/sandbox-exec", Args: append([]string{"sandbox-exec", "-p", profile.String()}, argv...)}
}

func waitSplitProcess(cmd *exec.Cmd) <-chan struct{} {
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	return done
}

func stopSplitProcess(cmd *exec.Cmd, done <-chan struct{}) {
	select {
	case <-done:
		return
	default:
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

func bridgeSplitExecutor(ctx context.Context, listener net.Listener, input io.WriteCloser, output io.ReadCloser) error {
	stop := context.AfterFunc(ctx, func() { _ = listener.Close(); _ = input.Close(); _ = output.Close() })
	defer stop()
	connection, err := listener.Accept()
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	stopConnection := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopConnection()
	_ = listener.Close()
	copied := make(chan error, 1)
	go func() { _, err := io.Copy(input, connection); _ = input.Close(); copied <- err }()
	_, err = io.Copy(connection, output)
	_ = connection.Close()
	_ = input.Close()
	_ = output.Close()
	return errors.Join(err, <-copied)
}
