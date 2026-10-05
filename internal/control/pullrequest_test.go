package control

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/operation"
	"github.com/getjump/airbag/outbox"
)

func prIntent(root string) outbox.Intent {
	return outbox.Intent{Cwd: root, Argv: []string{"gh", "pr", "create", "--repo", "getjump/airbag", "--base", "main", "--head", "work", "--title", "Fix", "--body", "reviewed"},
		Request: &operation.Request{Schema: operation.Schema, Kind: operation.CreatePullRequest, PullRequest: &operation.PullRequest{Repository: "getjump/airbag", Base: "main", Head: "work", HeadCommit: strings.Repeat("a", 40), Title: "Fix", Body: "reviewed"}}}
}

func TestTypedCaptureCannotFallBackToHostArgv(t *testing.T) {
	s := deferServer(t, "defer: [gh pr create]\n")
	for _, mutate := range []func(*outbox.Intent){
		func(in *outbox.Intent) { in.Request = nil },
		func(in *outbox.Intent) { in.CaptureError = "capture failed" },
		func(in *outbox.Intent) { in.Request.PullRequest.Repository = "other/project" },
		func(in *outbox.Intent) { in.Argv = append(in.Argv, "--fill") },
		func(in *outbox.Intent) { in.Request.PullRequest.Body = "different" },
	} {
		in := prIntent(s.Root)
		mutate(&in)
		d := ask(t, s, in)
		if d.Refused == "" || d.Queued != nil || d.Run {
			t.Fatalf("unsafe fallback: %+v", d)
		}
	}
	in := prIntent(s.Root)
	d := ask(t, s, in)
	if d.Queued == nil || d.Queued.Kind != outbox.KindPullRequest || d.Result == nil || d.Result.Outcome != operation.Queued || d.Result.RequestDigest == "" {
		t.Fatalf("not a queued typed result: %+v", d)
	}
}

func TestPRBodyFileMatchesCapturedBytes(t *testing.T) {
	s := deferServer(t, "defer: [gh pr create]\n")
	in := prIntent(s.Root)
	in.Argv[len(in.Argv)-2], in.Argv[len(in.Argv)-1] = "--body-file", "notes.md"
	in.Files = map[string]string{filepath.Join(s.Root, "notes.md"): strings.TrimPrefix(operation.Hash([]byte("reviewed")), "sha256:")}
	if d := ask(t, s, in); d.Queued == nil {
		t.Fatalf("body not queued: %+v", d)
	}
	in.Files[filepath.Join(s.Root, "notes.md")] = "different"
	if d := ask(t, s, in); !strings.Contains(d.Refused, "digest") {
		t.Fatalf("mismatched file captured: %+v", d)
	}
}

func TestTypedPolicySeesDestinationAndDigest(t *testing.T) {
	s := deferServer(t, `defer: [gh pr create]
rules:
  - name: only-our-repo
    when: effect.kind == "github.pull_request.create" && effect.target != "getjump/airbag"
    verdict: deny
  - name: review-publication
    when: effect.kind == "github.pull_request.create"
    verdict: ask
`)
	in := prIntent(s.Root)
	d := ask(t, s, in)
	if !strings.Contains(d.Refused, "review-publication") {
		t.Fatalf("typed ask ignored: %+v", d)
	}
	in.Request.PullRequest.Body, in.Argv[len(in.Argv)-1] = "new body", "new body"
	second := ask(t, s, in)
	if !strings.Contains(d.Refused, "a-1") || !strings.Contains(second.Refused, "a-2") {
		t.Fatalf("asks not bound to payload: %s / %s", d.Refused, second.Refused)
	}
	in.Request.PullRequest.Repository, in.Argv[4] = "other/project", "other/project"
	if d := ask(t, s, in); !strings.Contains(d.Refused, "only-our-repo") {
		t.Fatalf("destination deny ignored: %+v", d)
	}
}
