package apply

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/getjump/airbag/internal/operation"
	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/term"
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
	p := it.Request.PullRequest
	endpoint := "repos/" + p.Repository
	data, err := githubAPI(s, gh, "GET", endpoint+"/git/ref/heads/"+url.PathEscape(p.Head), nil)
	if err != nil {
		return pendingPR(it, o, fmt.Errorf("cannot verify GitHub head: %w", err))
	}
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := json.Unmarshal(data, &ref); err != nil || ref.Object.SHA != p.HeadCommit {
		return pendingPR(it, o, fmt.Errorf("GitHub head does not match the approved commit; push that exact commit to %s first", p.Head))
	}
	// Recheck the local selection after the potentially slow remote read.
	if err := selectedCommit(s, *p); err != nil {
		return pendingPR(it, o, err)
	}
	payload, err := json.Marshal(struct {
		Title               string `json:"title"`
		Body                string `json:"body"`
		Head                string `json:"head"`
		Base                string `json:"base"`
		Draft               bool   `json:"draft"`
		MaintainerCanModify bool   `json:"maintainer_can_modify"`
	}{Title: p.Title, Body: p.Body, Head: p.Head, Base: p.Base, Draft: p.Draft})
	if err != nil {
		return "", err
	}
	if it.Status == outbox.Pending {
		if err := box.Approve(it.ID, it.RequestDigest); err != nil {
			return "", err
		}
	}
	if err := box.Claim(it.ID, it.RequestDigest); err != nil {
		return "", err
	}
	data, err = githubAPI(s, gh, "POST", endpoint+"/pulls", payload)
	result := operation.Result{Outcome: operation.Uncertain, Ticket: it.ID, RequestDigest: it.RequestDigest}
	it.Status = outbox.Unknown
	if err == nil {
		if prURL, valid := exactPR(data, *p); valid {
			it.Status, result.Outcome, result.Value = outbox.Done, operation.Succeeded, prURL
		} else {
			result.Value = "GitHub response did not attest the exact request; reconcile the remote PR manually"
		}
	} else {
		// CLI failure/timeout does not establish whether GitHub accepted POST.
		result.Value = "publication may have reached GitHub; inspect the remote before making another request"
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

func githubAPI(s *session.Session, prog, method, endpoint string, payload []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := []string{"api", "--hostname", "github.com", "--method", method, "https://api.github.com/" + endpoint}
	if payload != nil {
		args = append(args, "--input", "-")
	}
	cmd := exec.CommandContext(ctx, prog, args...) //nolint:gosec // fixed gh api handler, validated repository/ref, JSON on stdin
	// No repository discovery, repo-local aliases, or agent-controlled cwd.
	cmd.Dir, cmd.Env = filepath.Dir(s.Workspace), publicationEnv()
	cmd.Stdin = bytes.NewReader(payload)
	out := &boundedOutput{limit: 2 << 20}
	cmd.Stdout, cmd.Stderr = out, io.Discard
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("GitHub API %s failed: %w", method, err)
	}
	if out.overflow {
		return nil, fmt.Errorf("GitHub API response exceeded the size limit")
	}
	return out.Bytes(), nil
}

func exactPR(data []byte, p operation.PullRequest) (string, bool) {
	type repo struct {
		FullName string `json:"full_name"`
	}
	type branch struct {
		Ref  string `json:"ref"`
		SHA  string `json:"sha"`
		Repo repo   `json:"repo"`
	}
	var response struct {
		Number int    `json:"number"`
		URL    string `json:"html_url"`
		Title  string `json:"title"`
		Body   string `json:"body"`
		Draft  *bool  `json:"draft"`
		Head   branch `json:"head"`
		Base   branch `json:"base"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return "", false
	}
	// GitHub names owners and repositories case-insensitively and answers
	// with its own spelling of them; branches and the rest are exact.
	wantURL := "https://github.com/" + p.Repository + "/pull/" + strconv.Itoa(response.Number)
	valid := response.Number > 0 && strings.EqualFold(response.URL, wantURL) && response.Title == p.Title && response.Body == p.Body && response.Draft != nil && *response.Draft == p.Draft &&
		response.Head.SHA == p.HeadCommit && response.Head.Ref == p.Head && response.Base.Ref == p.Base &&
		strings.EqualFold(response.Head.Repo.FullName, p.Repository) && strings.EqualFold(response.Base.Repo.FullName, p.Repository)
	return response.URL, valid
}
