package shim

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/secretfs"
	"github.com/getjump/airbag/operation"
)

// capturePullRequest freezes the body and resolves a literal branch inside the
// agent's workspace. Both are untrusted proposals; the host checks the shape,
// selected result and remote head again before execution. It also returns
// where the body file really is, links on the way resolved: O_NOFOLLOW sees
// only the last name, and a linked directory before it could lead out of the
// workspace. The host refuses the call when that place is outside.
func capturePullRequest(argv []string, cwd string) (*operation.Request, string, error) {
	args, matched, err := operation.ParsePullRequest(argv)
	if !matched {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	p := args.PullRequest
	if !operation.ValidBranch(p.Head) {
		return nil, "", fmt.Errorf("invalid PR head branch")
	}
	real := ""
	if args.BodyFile != "" {
		path := args.BodyFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(cwd, path)
		}
		if secretfs.IsSecret(filepath.Base(path)) {
			return nil, "", fmt.Errorf("PR body names a secret file")
		}
		// The file itself, not a link: through a link the name checked
		// above could stand for a secret file somewhere else. Opened
		// without blocking, so a FIFO is refused below instead of waiting
		// for a writer.
		f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return nil, "", fmt.Errorf("PR body must be a regular workspace file, not a link: %w", err)
		}
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			_ = f.Close()
			return nil, "", fmt.Errorf("PR body must be a regular workspace file")
		}
		data, readErr := io.ReadAll(io.LimitReader(f, operation.MaxBody+1))
		closeErr := f.Close()
		if readErr != nil {
			return nil, "", fmt.Errorf("read PR body: %w", readErr)
		}
		if closeErr != nil {
			return nil, "", fmt.Errorf("close PR body: %w", closeErr)
		}
		// The resolved name must still be the file read, or a link
		// swapped meanwhile could point the check somewhere else.
		real, err = filepath.EvalSymlinks(path)
		if err != nil {
			return nil, "", fmt.Errorf("resolve PR body: %w", err)
		}
		if rst, err := os.Lstat(real); err != nil || !os.SameFile(st, rst) {
			return nil, "", fmt.Errorf("PR body changed while it was read")
		}
		p.Body = string(data)
	}
	ref := "refs/heads/" + p.Head + "^{commit}"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-c", "core.fsmonitor=false", "rev-parse", "--verify", ref) //nolint:gosec // a literal branch validated above, not a revision expression
	cmd.Dir = cwd
	data, err := cmd.Output()
	if err != nil {
		return nil, "", fmt.Errorf("resolve PR head %s: %w", p.Head, err)
	}
	p.HeadCommit = strings.TrimSpace(string(data))
	r := &operation.Request{Schema: operation.Schema, Kind: operation.CreatePullRequest, PullRequest: &p}
	if err := r.Validate(); err != nil {
		return nil, "", err
	}
	return r, real, nil
}
