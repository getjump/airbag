package apply

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/getjump/airbag/githubpr"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/term"
	"github.com/getjump/airbag/operation"
	"github.com/getjump/airbag/outbox"
)

// runPullRequest executes only the typed payload, never the queued argv. A
// successful preflight is not an atomic lock on GitHub's branch: validate the
// returned PR too and report uncertainty if the branch raced publication.
func runPullRequest(s *session.Session, box *outbox.Box, it outbox.Intent, in *bufio.Reader, o Options) (string, error) {
	if it.Request == nil {
		return "", fmt.Errorf("intent %s has no typed request", it.ID)
	}
	preview, err := it.Request.Preview()
	if err != nil {
		return "", err
	}
	if o.Yes {
		fmt.Fprintf(o.Out, "intent %s left pending: typed external actions are approved one by one; run airbag apply %s without --yes\n", it.ID, s.ID)
		return it.Status, nil
	}
	safe := term.Safe(o.Out)
	outbox.WritePreview(safe, it.ID, it.Status, preview)
	safe.Flush()
	if !confirm(in, o, "Approve this exact request and publish it with your host GitHub credentials?") {
		return reject(box, it, "human declined the typed request", o)
	}
	gh, err := trustedTool(s, "gh")
	if err != nil {
		return pendingPR(it, o, err)
	}
	if err := selectedCommit(s, *it.Request.PullRequest); err != nil {
		return pendingPR(it, o, err)
	}
	handler := githubpr.Handler{Call: func(ctx context.Context, method, endpoint string, payload []byte) ([]byte, error) {
		body, code, err := githubAPI(ctx, s, gh, method, endpoint, payload)
		if err != nil && code >= 400 && code < 500 {
			return body, &githubpr.HTTPError{StatusCode: code, Body: body}
		}
		return body, err
	}}
	prepared, err := handler.Prepare(context.Background(), *it.Request)
	if err != nil {
		return pendingPR(it, o, err)
	}
	if err := selectedCommit(s, *it.Request.PullRequest); err != nil {
		return pendingPR(it, o, err)
	}
	if prepared.Digest() != it.RequestDigest {
		return "", fmt.Errorf("prepared request differs from the queued request")
	}
	if it.Status == outbox.Pending {
		if err := box.Approve(it.ID, it.RequestDigest); err != nil {
			return "", err
		}
	}
	if err := box.Claim(it.ID, it.RequestDigest); err != nil {
		return "", err
	}
	result := prepared.Publish(context.Background())
	result.Ticket = it.ID
	it.Status = outbox.Unknown
	switch result.Outcome {
	case operation.Succeeded:
		it.Status = outbox.Done
	case operation.Failure:
		it.Status = outbox.Failed
	}
	encoded, encodeErr := json.Marshal(result)
	if encodeErr != nil {
		return "", encodeErr
	}
	it.Output = string(encoded)
	if err := box.Update(it); err != nil {
		return "", fmt.Errorf("publication attempted but outcome not recorded: %w", err)
	}
	fmt.Fprintf(o.Out, "intent %s: %s (%s)\n", it.ID, result.Outcome, result.Value)
	return it.Status, nil
}

func pendingPR(it outbox.Intent, o Options, err error) (string, error) {
	fmt.Fprintf(o.Out, "intent %s left pending: %s\n", it.ID, err)
	return it.Status, nil
}

func trustedTool(s *session.Session, name string) (string, error) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s is not available on the host", name)
	}
	p, err = filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	p, err = filepath.Abs(p)
	if err != nil || within(p, s.Workspace) || (s.Clone && within(p, s.CloneDir())) {
		return "", fmt.Errorf("%s must resolve to a host program outside the workspace", name)
	}
	return p, nil
}

func selectedCommit(s *session.Session, p operation.PullRequest) error {
	if s.Branch == "" && s.Status != session.StatusApplied {
		return fmt.Errorf("the session has not been fully applied; finish apply or explicitly import its commit with --branch before publication")
	}
	branch := p.Head
	if s.Branch != "" {
		branch = s.Branch
	}
	if !operation.ValidBranch(branch) {
		return fmt.Errorf("invalid selected branch")
	}
	prog, err := trustedTool(s, "git")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, prog, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", s.Workspace, "rev-parse", "--verify", "refs/heads/"+branch+"^{commit}") //nolint:gosec // trusted host tool and a validated literal branch
	cmd.Env = publicationEnv()
	data, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(data)) != p.HeadCommit {
		return fmt.Errorf("selected local branch %s does not match queued commit %s; import the agent's committed result first", branch, p.HeadCommit)
	}
	return nil
}

// publicationEnv uses host credentials but ignores inherited git routing and
// gh repository/host/debug settings. The API handler also names github.com.
func publicationEnv() []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "GIT_") || key == "GH_HOST" || key == "GH_REPO" || key == "GH_DEBUG" || key == "GH_HTTP_UNIX_SOCKET" || key == "GH_PROMPT_DISABLED" {
			continue
		}
		env = append(env, entry)
	}
	return append(env, "GIT_TERMINAL_PROMPT=0", "GH_PROMPT_DISABLED=1")
}

// boundedOutput caps memory even when a failing CLI emits arbitrary data.
type boundedOutput struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (w *boundedOutput) Write(data []byte) (int, error) {
	n := len(data)
	left := w.limit - w.Len()
	if n > left {
		w.overflow = true
		data = data[:left]
	}
	_, _ = w.Buffer.Write(data)
	return n, nil
}

// githubAPI returns the response body and its HTTP status: 0 when gh
// printed no status line, as when it failed before GitHub answered.
func githubAPI(ctx context.Context, s *session.Session, prog, method, endpoint string, payload []byte) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	args := []string{"api", "--hostname", "github.com", "--method", method, "https://api.github.com/" + endpoint, "--include"}
	if payload != nil {
		args = append(args, "--input", "-")
	}
	cmd := exec.CommandContext(ctx, prog, args...) //nolint:gosec // fixed gh api handler, validated repository/ref, JSON on stdin
	// No repository discovery, repo-local aliases, or agent-controlled cwd.
	cmd.Dir, cmd.Env = filepath.Dir(s.Workspace), publicationEnv()
	cmd.Stdin = bytes.NewReader(payload)
	out := &boundedOutput{limit: 2 << 20}
	cmd.Stdout, cmd.Stderr = out, io.Discard
	runErr := cmd.Run()
	code, body := splitResponse(out.Bytes())
	if runErr != nil {
		return body, code, fmt.Errorf("GitHub API %s failed: %w", method, runErr)
	}
	if out.overflow {
		return nil, code, fmt.Errorf("GitHub API response exceeded the size limit")
	}
	return body, code, nil
}

// splitResponse separates what gh api --include prints: a status line
// and headers, a blank line, the body. Output without a status line is
// all body, with status 0.
func splitResponse(out []byte) (int, []byte) {
	if !bytes.HasPrefix(out, []byte("HTTP/")) {
		return 0, out
	}
	head, body, ok := bytes.Cut(out, []byte("\r\n\r\n"))
	if !ok {
		head, body, ok = bytes.Cut(out, []byte("\n\n"))
	}
	if !ok {
		return 0, nil
	}
	line, _, _ := bytes.Cut(head, []byte("\n"))
	f := strings.Fields(string(line))
	if len(f) < 2 {
		return 0, body
	}
	code, err := strconv.Atoi(f[1])
	if err != nil {
		return 0, body
	}
	return code, body
}

func exactPR(data []byte, p operation.PullRequest) (string, bool) {
	return githubpr.MatchResponse(data, p)
}
