//go:build darwin

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// probe is the state the checks share.
type probe struct {
	opts    options
	dir     string // the temporary directory, resolved
	home    string
	tag     string // marks the Seatbelt check's denials in the log
	mnt     string // the NFS mount point, once mounted
	mounted bool
	srv     *nfsServer
}

// run runs a command with a timeout and returns its combined output.
func run(timeout time.Duration, dir string, name string, args ...string) (string, error) {
	return runEnv(timeout, dir, nil, name, args...)
}

// runEnv is run with the environment env (nil: this process's).
func runEnv(timeout time.Duration, dir string, env []string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // the probe's own commands, with its own arguments
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out after %s", timeout)
	}
	return string(out), err
}

// shq quotes s for sh.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// gitArgs are prepended to every git command the probe runs.
var gitArgs = []string{"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "user.email=probe@example.com", "-c", "user.name=probe"}

func seconds(d time.Duration) float64 { return d.Seconds() }

func timed(f func() error) (time.Duration, error) {
	t := time.Now()
	err := f()
	return time.Since(t), err
}

func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o644) }

// refusedNote says how many MOUNT requests the server refused, for N1.
func refusedNote(late, other int) string {
	return fmt.Sprintf("the probe's NFS server refused %d mount request(s) that named the armed path after its grant, and %d that named another path", late, other)
}

// clip shortens command output for a reason or a detail.
func clip(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + " ..."
}
