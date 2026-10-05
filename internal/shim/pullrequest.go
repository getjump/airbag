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

	"github.com/getjump/airbag/internal/secretfs"
	"github.com/getjump/airbag/operation"
)

// capturePullRequest freezes the body and resolves a literal branch inside the
// agent's workspace. Both are untrusted proposals; the host checks the shape,
// selected result and remote head again before execution.
func capturePullRequest(argv []string, cwd string) (*operation.Request, error) {
	args, matched, err := operation.ParsePullRequest(argv)
	if !matched {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p := args.PullRequest
	if !operation.ValidBranch(p.Head) {
		return nil, fmt.Errorf("invalid PR head branch")
	}
	if args.BodyFile != "" {
		path := args.BodyFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(cwd, path)
		}
		if secretfs.IsSecret(filepath.Base(path)) {
			return nil, fmt.Errorf("PR body names a secret file")
		}
		if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
			return nil, fmt.Errorf("PR body must be a regular workspace file")
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("read PR body: %w", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(f, operation.MaxBody+1))
		closeErr := f.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read PR body: %w", readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close PR body: %w", closeErr)
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
		return nil, fmt.Errorf("resolve PR head %s: %w", p.Head, err)
	}
	p.HeadCommit = strings.TrimSpace(string(data))
	r := &operation.Request{Schema: operation.Schema, Kind: operation.CreatePullRequest, PullRequest: &p}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}
