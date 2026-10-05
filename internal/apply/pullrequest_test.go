package apply

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/operation"
	"github.com/getjump/airbag/outbox"
)

func commitForPR(t *testing.T, ws string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", ws}, args...)...) //nolint:gosec // test-owned git fixture
	cmd.Env = publicationEnv()
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %q: %s %v", args, data, err)
	}
	return strings.TrimSpace(string(data))
}

func prFixture(t *testing.T) (*session.Session, *outbox.Box, outbox.Intent) {
	t.Helper()
	s, b := testBox(t)
	s.Status = session.StatusApplied // fixture represents the imported workspace
	commitForPR(t, s.Workspace, "init", "-q", "-b", "work")
	commitForPR(t, s.Workspace, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "reviewed", "--allow-empty")
	sha := commitForPR(t, s.Workspace, "rev-parse", "HEAD")
	r := &operation.Request{Schema: operation.Schema, Kind: operation.CreatePullRequest, PullRequest: &operation.PullRequest{Repository: "getjump/airbag", Base: "main", Head: "work", HeadCommit: sha, Title: "Reviewed fix", Body: "frozen body\n", Draft: true}}
	it, err := b.Push(outbox.Intent{Kind: outbox.KindPullRequest, Cwd: s.Workspace, Argv: []string{"gh", "pr", "create", "--fill", "--web"}, Request: r})
	if err != nil {
		t.Fatal(err)
	}
	return s, b, it
}

func shellFixtureLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func mockPR(t *testing.T, p operation.PullRequest, mode string) (string, string) {
	t.Helper()
	bin, log := t.TempDir(), filepath.Join(t.TempDir(), "gh")
	response := map[string]any{"number": 7, "html_url": "https://github.com/" + p.Repository + "/pull/7", "title": p.Title, "body": p.Body, "draft": p.Draft,
		"head": map[string]any{"sha": p.HeadCommit, "ref": p.Head, "repo": map[string]string{"full_name": p.Repository}},
		"base": map[string]any{"ref": p.Base, "repo": map[string]string{"full_name": p.Repository}}}
	if mode == "race" {
		response["head"].(map[string]any)["sha"] = strings.Repeat("b", 40)
	}
	post, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	sha := p.HeadCommit
	if mode == "remote-changed" {
		sha = strings.Repeat("b", 40)
	}
	postAction := "printf '%s\\n' " + shellFixtureLiteral(string(post))
	if mode == "ambiguous" {
		postAction = "exit 1"
	}
	if mode == "refused" { // gh api --include on a 422, then gh's own exit
		postAction = "printf '%s' " + shellFixtureLiteral("HTTP/2.0 422 Unprocessable Entity\r\nContent-Type: application/json\r\n\r\n"+
			`{"message":"Validation Failed","errors":[{"message":"A pull request already exists for getjump:work."}]}`+"\n") + "\nexit 1"
	}
	script := "#!/bin/sh\necho \"$*\" >> " + shellFixtureLiteral(log) + "\n" +
		"if [ \"$5\" = GET ]; then printf '%s\\n' " + shellFixtureLiteral(`{"object":{"sha":"`+sha+`"}}`) + "; else\n" +
		"cat > " + shellFixtureLiteral(log+".payload") + "\n" + postAction + "\nfi\n"
	prog := filepath.Join(bin, "gh")
	if err := os.WriteFile(prog, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	return log, prog
}

func runPRFixture(t *testing.T, s *session.Session, b *outbox.Box, yes bool, input string) string {
	t.Helper()
	var out bytes.Buffer
	if err := runIntents(s, b, false, bufio.NewReader(strings.NewReader(input)), Options{Yes: yes, Out: &out}); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestTypedPublicationUsesFrozenPayloadOnce(t *testing.T) {
	s, b, it := prFixture(t)
	log, _ := mockPR(t, *it.Request.PullRequest, "ok")
	if out := runPRFixture(t, s, b, true, ""); !strings.Contains(out, "without --yes") || status(t, b, it.ID) != outbox.Pending || ran(log) != "" {
		t.Fatal("--yes used authority")
	}
	// The selected branch can have a different name. Only its exact commit
	// is evidence of the reviewed result; the remote target is never rewritten.
	commitForPR(t, s.Workspace, "branch", "chosen")
	s.Branch = "chosen"
	out := runPRFixture(t, s, b, false, "y\n")
	if status(t, b, it.ID) != outbox.Done || !strings.Contains(out, "completed") {
		t.Fatalf("not completed: %s", out)
	}
	var payload map[string]any
	data, err := os.ReadFile(log + ".payload")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["body"] != "frozen body\n" || payload["head"] != "work" || payload["draft"] != true || payload["maintainer_can_modify"] != false {
		t.Fatalf("wrong payload: %s", data)
	}
	if strings.Contains(ran(log), "--fill") || strings.Count(ran(log), "--method POST") != 1 {
		t.Fatalf("executed producer argv: %s", ran(log))
	}
	_ = runPRFixture(t, s, b, false, "y\n")
	if strings.Count(ran(log), "--method POST") != 1 {
		t.Fatal("published twice")
	}
}

func TestPRPreflightAndUncertainty(t *testing.T) {
	for _, mode := range []string{"local-changed", "remote-changed", "ambiguous", "race"} {
		t.Run(mode, func(t *testing.T) {
			s, b, it := prFixture(t)
			log, _ := mockPR(t, *it.Request.PullRequest, mode)
			if mode == "local-changed" {
				commitForPR(t, s.Workspace, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "later", "--allow-empty")
			}
			_ = runPRFixture(t, s, b, false, "y\n")
			want := outbox.Pending
			if mode == "ambiguous" || mode == "race" {
				want = outbox.Unknown
			}
			if status(t, b, it.ID) != want {
				t.Fatalf("status %s, expected %s", status(t, b, it.ID), want)
			}
			calls := strings.Count(ran(log), "--method POST")
			if want == outbox.Pending && calls != 0 {
				t.Fatal("published changed commit")
			}
			if want == outbox.Unknown {
				_ = runPRFixture(t, s, b, false, "y\n")
				if calls != 1 || strings.Count(ran(log), "--method POST") != 1 {
					t.Fatal("retried uncertain POST")
				}
			}
		})
	}
}

func TestRunningTypedRequestIsRecoveredAndBlocksFollowingRequests(t *testing.T) {
	s, b, it := prFixture(t)
	log, _ := mockPR(t, *it.Request.PullRequest, "ok")
	if err := b.Approve(it.ID, it.RequestDigest); err != nil {
		t.Fatal(err)
	}
	if err := b.Claim(it.ID, it.RequestDigest); err != nil {
		t.Fatal(err)
	}
	next, err := b.Push(outbox.Intent{Kind: outbox.KindPullRequest, Request: it.Request})
	if err != nil {
		t.Fatal(err)
	}
	_ = runPRFixture(t, s, b, false, "y\n")
	_ = runPRFixture(t, s, b, false, "y\n")
	if status(t, b, it.ID) != outbox.Unknown || status(t, b, next.ID) != outbox.Pending || ran(log) != "" {
		t.Fatal("recovery repeated or bypassed an uncertain effect")
	}
}

func TestPublicationDoesNotUseWorkspaceGh(t *testing.T) {
	s, b, it := prFixture(t)
	log, prog := mockPR(t, *it.Request.PullRequest, "ok")
	if err := os.Symlink(prog, filepath.Join(s.Workspace, "gh")); err != nil {
		t.Fatal(err)
	}
	// Resolve through a workspace symlink to a trusted external file: allowed.
	t.Setenv("PATH", s.Workspace+":"+os.Getenv("PATH"))
	if _, err := trustedTool(s, "gh"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.Workspace, "gh")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Workspace, "gh"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = runPRFixture(t, s, b, false, "y\n")
	if status(t, b, it.ID) != outbox.Pending || ran(log) != "" {
		t.Fatal("used an agent-controlled program")
	}
}

func TestPreapprovedRequestStillRequiresCurrentProof(t *testing.T) {
	s, b, it := prFixture(t)
	log, _ := mockPR(t, *it.Request.PullRequest, "remote-changed")
	if err := b.Approve(it.ID, it.RequestDigest); err != nil {
		t.Fatal(err)
	}
	_ = runPRFixture(t, s, b, false, "y\n")
	if status(t, b, it.ID) != string(operation.Approved) || strings.Contains(ran(log), "--method POST") {
		t.Fatal("stored approval bypassed preflight")
	}
}

func TestLiveExecutorCannotBeMarkedUnknown(t *testing.T) {
	s, b, it := prFixture(t)
	if err := b.Approve(it.ID, it.RequestDigest); err != nil {
		t.Fatal(err)
	}
	if err := b.Claim(it.ID, it.RequestDigest); err != nil {
		t.Fatal(err)
	}
	lock, err := b.LockExecution()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	var out bytes.Buffer
	if err := runIntents(s, b, false, nil, Options{Yes: true, Out: &out}); err == nil {
		t.Fatal("ran recovery alongside a live executor")
	}
	if status(t, b, it.ID) != outbox.Running {
		t.Fatal("recovered the live executor as crashed")
	}
}

func TestAbsentDraftFlagDoesNotAttestPublishedRequest(t *testing.T) {
	p := operation.PullRequest{Repository: "getjump/airbag", Base: "main", Head: "work", HeadCommit: strings.Repeat("a", 40), Title: "Fix", Body: "body"}
	response := map[string]any{"number": 7, "html_url": "https://github.com/getjump/airbag/pull/7", "title": p.Title, "body": p.Body,
		"head": map[string]any{"ref": p.Head, "sha": p.HeadCommit, "repo": map[string]string{"full_name": p.Repository}},
		"base": map[string]any{"ref": p.Base, "repo": map[string]string{"full_name": p.Repository}}}
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid := exactPR(data, p); valid {
		t.Fatal("missing flag became a confirmed nondraft PR")
	}
	response["draft"] = false
	data, err = json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid := exactPR(data, p); !valid {
		t.Fatal("explicit matching flag was not attested")
	}
}

func TestPublishedPRMatchesRepositoryInGitHubsSpelling(t *testing.T) {
	p := operation.PullRequest{Repository: "getjump/airbag", Base: "main", Head: "work", HeadCommit: strings.Repeat("a", 40), Title: "Fix", Body: "body"}
	response := func(repo, head string) []byte {
		data, err := json.Marshal(map[string]any{"number": 7, "html_url": "https://github.com/" + repo + "/pull/7", "title": p.Title, "body": p.Body, "draft": false,
			"head": map[string]any{"ref": head, "sha": p.HeadCommit, "repo": map[string]string{"full_name": repo}},
			"base": map[string]any{"ref": p.Base, "repo": map[string]string{"full_name": repo}}})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if _, valid := exactPR(response("GetJump/Airbag", p.Head), p); !valid {
		t.Fatal("GitHub's own spelling of the repository was not attested")
	}
	if _, valid := exactPR(response("getjump/airbag2", p.Head), p); valid {
		t.Fatal("another repository was attested")
	}
	if _, valid := exactPR(response("GetJump/Airbag", "Work"), p); valid {
		t.Fatal("a branch differing in case was attested")
	}
}

func TestPartialApplyDoesNotSelectAnEntireCommitForPublication(t *testing.T) {
	s, b, it := prFixture(t)
	log, _ := mockPR(t, *it.Request.PullRequest, "ok")
	// The ref already names the full commit, but a partial file import is not
	// permission to publish every change contained in that commit.
	s.Status = session.StatusStopped
	_ = runPRFixture(t, s, b, false, "y\n")
	if status(t, b, it.ID) != outbox.Pending || ran(log) != "" {
		t.Fatal("partial file selection authorized the full commit")
	}
}

// A request GitHub answered and refused created nothing: it fails, is
// not sent again, and holds nothing back in later runs.
func TestRefusedPublicationFails(t *testing.T) {
	s, b, it := prFixture(t)
	log, _ := mockPR(t, *it.Request.PullRequest, "refused")
	out := runPRFixture(t, s, b, false, "y\n")
	if status(t, b, it.ID) != outbox.Failed || !strings.Contains(out, "HTTP 422") || !strings.Contains(out, "already exists") {
		t.Fatalf("refusal not recorded as failed: %s %q", status(t, b, it.ID), out)
	}
	all, err := b.List()
	if err != nil {
		t.Fatal(err)
	}
	if r := all[0].TypedResult(); r == nil || r.Outcome != operation.Failure {
		t.Fatalf("result: %+v", r)
	}
	_ = runPRFixture(t, s, b, false, "y\n")
	if strings.Count(ran(log), "--method POST") != 1 {
		t.Fatal("sent a refused request again")
	}
}

// A push held because the session's work is on a branch does not hold a
// typed PR back: the PR checks for itself that the remote has the commit.
func TestHeldPushDoesNotHoldTypedPR(t *testing.T) {
	s, b, it := prFixture(t)
	push, err := b.Push(outbox.Intent{Kind: outbox.KindPush, Argv: []string{"git", "push", "origin", "work"}, Cwd: s.Workspace})
	if err != nil {
		t.Fatal(err)
	}
	pr, err := b.Push(outbox.Intent{Kind: outbox.KindPullRequest, Cwd: s.Workspace, Argv: it.Argv, Request: it.Request})
	if err != nil {
		t.Fatal(err)
	}
	// Only the second request is under test: settle the first.
	if err := b.Update(outbox.Intent{ID: it.ID, Status: outbox.Rejected, RequestDigest: it.RequestDigest}); err != nil {
		t.Fatal(err)
	}
	s.Branch = "work"
	log, _ := mockPR(t, *it.Request.PullRequest, "ok")
	out := runPRFixture(t, s, b, false, "y\n")
	if status(t, b, push.ID) != outbox.Pending || status(t, b, pr.ID) != outbox.Done || !strings.Contains(ran(log), "--method POST") {
		t.Fatalf("push %s, PR %s: %q", status(t, b, push.ID), status(t, b, pr.ID), out)
	}
}

func TestPublishedPRMustMatchTitleBodyAndBase(t *testing.T) {
	p := operation.PullRequest{Repository: "getjump/airbag", Base: "main", Head: "work", HeadCommit: strings.Repeat("a", 40), Title: "Fix", Body: "body"}
	for _, change := range []func(m map[string]any){
		func(map[string]any) {},
		func(m map[string]any) { m["title"] = "Other" },
		func(m map[string]any) { m["body"] = "other" },
		func(m map[string]any) { m["base"].(map[string]any)["ref"] = "release" },
	} {
		m := map[string]any{"number": 7, "html_url": "https://github.com/getjump/airbag/pull/7", "title": p.Title, "body": p.Body, "draft": false,
			"head": map[string]any{"ref": p.Head, "sha": p.HeadCommit, "repo": map[string]string{"full_name": p.Repository}},
			"base": map[string]any{"ref": p.Base, "repo": map[string]string{"full_name": p.Repository}}}
		change(m)
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		_, valid := exactPR(data, p)
		if want := m["title"] == p.Title && m["body"] == p.Body && m["base"].(map[string]any)["ref"] == p.Base; valid != want {
			t.Fatalf("attested %v, want %v: %s", valid, want, data)
		}
	}
}

func TestSplitResponse(t *testing.T) {
	for in, want := range map[string]int{
		"HTTP/2.0 201 Created\r\nX: y\r\n\r\n{}":  201,
		"HTTP/1.1 422 Unprocessable Entity\n\n{}": 422,
		"{}":                         0,
		"HTTP/2.0 garbage\r\n\r\n{}": 0,
	} {
		if code, body := splitResponse([]byte(in)); code != want || string(body) != "{}" {
			t.Errorf("splitResponse(%q) = %d %q, want %d", in, code, body, want)
		}
	}
}
